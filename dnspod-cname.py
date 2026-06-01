#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
外部域名 Cloudflare CNAME 工具（限制每个优选子域名最多 2 个外部域名）
- 从外部 URL 获取域名列表
- 检测每个域名的 A 记录 IP 是否属于 Cloudflare
- 若属于 Cloudflare IP，则先删除该域名的所有现有记录，再添加 CNAME 到指定优选子域名
- 每个优选子域名最多被 2 个外部域名指向（轮询分配直到配额用尽）
- 支持 Telegram 通知
"""

import os
import sys
import time
import json
import hashlib
import hmac
import ipaddress
import requests
from typing import List, Dict, Tuple

# ========== 环境变量读取 ==========
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY")
# 优选子域名所在的根域名（CNAME 目标会指向 SUB_DOMAINS[i].DOMAIN）
DOMAIN = os.environ.get("DOMAIN")

# 用于 CNAME 轮询的优选子域名列表
SUB_DOMAINS = os.environ.get("SUB_DOMAINS", "1-1,1-2,2-1,2-2").split(",")

# 每个优选子域名最多被几个外部域名 CNAME 指向
MAX_CNAME_PER_SUB = 2

# 外部域名列表 URL（每行一个域名）
EXTERNAL_DOMAINS_URL = os.environ.get(
    "EXTERNAL_DOMAINS_URL",
    "https://raw.githubusercontent.com/leung7963/CFIPS/main/domain.js"
)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ========== 腾讯云 API 签名函数 ==========
def sign_v3(service: str, action: str, version: str, payload: dict,
            secret_id: str, secret_key: str, region: str = "",
            timestamp: int = None) -> Tuple[dict, str]:
    if timestamp is None:
        timestamp = int(time.time())
    http_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    ct = "application/json"
    canonical_headers = f"content-type:{ct}\nhost:dnspod.tencentcloudapi.com\n"
    signed_headers = "content-type;host"
    payload_str = json.dumps(payload, separators=(',', ':'))
    hashed_payload = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    canonical_request = "\n".join([http_method, canonical_uri, canonical_querystring,
                                   canonical_headers, signed_headers, hashed_payload])
    algorithm = "TC3-HMAC-SHA256"
    date = time.strftime("%Y-%m-%d", time.gmtime(timestamp))
    credential_scope = f"{date}/{service}/tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = "\n".join([algorithm, str(timestamp), credential_scope, hashed_canonical_request])
    secret_date = hmac.new(("TC3" + secret_key).encode("utf-8"), date.encode("utf-8"), hashlib.sha256).digest()
    secret_service = hmac.new(secret_date, service.encode("utf-8"), hashlib.sha256).digest()
    secret_signing = hmac.new(secret_service, "tc3_request".encode("utf-8"), hashlib.sha256).digest()
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    authorization = (f"{algorithm} Credential={secret_id}/{credential_scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")
    headers = {
        "Authorization": authorization,
        "Content-Type": ct,
        "Host": "dnspod.tencentcloudapi.com",
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Region": region
    }
    return headers, payload_str

# ========== Cloudflare IP 检测类 ==========
class CloudflareIPChecker:
    def __init__(self):
        self._ipv4_cidrs = []
        self._ipv6_cidrs = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 CF-CNAME-Tool/1.0'})

    def fetch_cidrs(self) -> bool:
        """获取 Cloudflare 官方 IP 范围"""
        try:
            resp_v4 = self.session.get("https://www.cloudflare.com/ips-v4", timeout=15)
            resp_v4.raise_for_status()
            self._ipv4_cidrs = [line.strip() for line in resp_v4.text.splitlines() if line.strip()]
        except Exception as e:
            print(f"获取 IPv4 CIDR 失败: {e}")
            return False

        try:
            resp_v6 = self.session.get("https://www.cloudflare.com/ips-v6", timeout=15)
            resp_v6.raise_for_status()
            self._ipv6_cidrs = [line.strip() for line in resp_v6.text.splitlines() if line.strip()]
        except Exception as e:
            print(f"获取 IPv6 CIDR 失败: {e}")

        return bool(self._ipv4_cidrs)

    def is_cloudflare_ip(self, ip_str: str) -> bool:
        """判断 IP 是否属于 Cloudflare"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return any(ip_obj in ipaddress.IPv4Network(cidr) for cidr in self._ipv4_cidrs)
            else:
                return any(ip_obj in ipaddress.IPv6Network(cidr) for cidr in self._ipv6_cidrs)
        except:
            return False

# ========== 腾讯云 DNS 管理类 ==========
class TencentDNSManager:
    def __init__(self, secret_id: str, secret_key: str):
        self.secret_id, self.secret_key = secret_id, secret_key
        self.session = requests.Session()

    def _call_api(self, action: str, payload: dict) -> dict:
        headers, body = sign_v3("dnspod", action, "2021-03-23", payload,
                                self.secret_id, self.secret_key)
        resp = self.session.post("https://dnspod.tencentcloudapi.com",
                                 headers=headers, data=body, timeout=10)
        return resp.json()

    def get_a_records(self, domain: str, sub: str = "@") -> List[dict]:
        """获取指定域名的 A 记录列表"""
        list_resp = self._call_api("DescribeRecordList", {"Domain": domain, "Subdomain": sub})
        records = list_resp.get("Response", {}).get("RecordList", [])
        return [r for r in records if r.get("Type") == "A"]

    def delete_all_records(self, domain: str, sub: str = "@"):
        """删除指定子域名的所有记录（A、AAAA、CNAME 等），确保无残留"""
        list_resp = self._call_api("DescribeRecordList", {"Domain": domain, "Subdomain": sub})
        records = list_resp.get("Response", {}).get("RecordList", [])
        for r in records:
            print(f"  正在删除记录: {r.get('Name')}.{domain} 类型: {r.get('Type')}")
            self._call_api("DeleteRecord", {"Domain": domain, "RecordId": r.get("RecordId")})

    def add_cname_record(self, domain: str, sub: str, target: str, line: str = "默认") -> bool:
        """添加 CNAME 记录，返回是否成功"""
        payload = {
            "Domain": domain,
            "SubDomain": sub,
            "RecordType": "CNAME",
            "RecordLine": line,
            "Value": target,
            "TTL": 600
        }
        resp = self._call_api("CreateRecord", payload)
        err = resp.get("Response", {}).get("Error")
        if err:
            print(f"  添加 CNAME 失败: {err.get('Message')}")
            return False
        print(f"  已添加 CNAME: {sub}.{domain} → {target}")
        return True

# ========== 通知类 ==========
class NotificationManager:
    @staticmethod
    def send_telegram(text: str):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=10)
        except Exception as e:
            print(f"TG 发送失败: {e}")

# ========== 外部域名获取 ==========
def fetch_external_domains(url: str) -> List[str]:
    """从 URL 获取域名列表，每行一个，去重并过滤"""
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = [line.strip().lower() for line in resp.text.splitlines() if line.strip()]
        domains = [d for d in lines if '.' in d]
        return list(set(domains))
    except Exception as e:
        print(f"获取外部域名列表失败: {e}")
        return []

# ========== 主程序 ==========
def main():
    requests.packages.urllib3.disable_warnings()
    print("=" * 60)
    print("外部域名 Cloudflare CNAME 工具")
    print(f"每个优选子域名最多指向 {MAX_CNAME_PER_SUB} 个外部域名")
    print("=" * 60)

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY or not DOMAIN:
        print("错误：缺少必要环境变量 TENCENT_SECRET_ID / TENCENT_SECRET_KEY / DOMAIN")
        sys.exit(1)

    cf_checker = CloudflareIPChecker()
    dns_mgr = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    if not cf_checker.fetch_cidrs():
        print("无法获取 Cloudflare IP 范围，退出。")
        sys.exit(1)

    external_domains = fetch_external_domains(EXTERNAL_DOMAINS_URL)
    if not external_domains:
        print("未获取到任何外部域名，退出。")
        return

    print(f"获取到 {len(external_domains)} 个外部域名，开始检测并设置 CNAME...")

    # 子域名配额计数
    sub_usage = {sub: 0 for sub in SUB_DOMAINS}
    results = []
    current_index = 0

    for ext_domain in external_domains:
        print(f"\n处理域名: {ext_domain}")
        try:
            # 1. 获取 A 记录（用于判断 IP）
            a_records = dns_mgr.get_a_records(ext_domain, sub="@")
            if not a_records:
                results.append(f"  {ext_domain}: 无 A 记录，跳过")
                continue

            first_ip = a_records[0].get("Value", "")
            if not first_ip:
                results.append(f"  {ext_domain}: A 记录无 IP 值，跳过")
                continue

            # 2. 判断是否 Cloudflare IP
            if not cf_checker.is_cloudflare_ip(first_ip):
                results.append(f"  ⚠️ {ext_domain}: IP {first_ip} 不是 Cloudflare IP，跳过")
                continue

            # 3. 查找一个未满的子域名
            target_sub = None
            for i in range(len(SUB_DOMAINS)):
                idx = (current_index + i) % len(SUB_DOMAINS)
                if sub_usage[SUB_DOMAINS[idx]] < MAX_CNAME_PER_SUB:
                    target_sub = SUB_DOMAINS[idx]
                    current_index = (idx + 1) % len(SUB_DOMAINS)  # 下次从这里开始
                    break

            if target_sub is None:
                results.append(f"  ❌ {ext_domain}: 所有优选子域名配额已满（每个 {MAX_CNAME_PER_SUB} 个），跳过")
                continue

            # 4. 删除原有所有记录（先清空，避免冲突）
            dns_mgr.delete_all_records(ext_domain, "@")

            # 5. 添加 CNAME
            cname_target = f"{target_sub}.{DOMAIN}."
            success = dns_mgr.add_cname_record(ext_domain, "@", cname_target)

            if success:
                sub_usage[target_sub] += 1
                results.append(f"  ✅ {ext_domain} → CNAME {cname_target} (子域名 {target_sub} 已用 {sub_usage[target_sub]}/{MAX_CNAME_PER_SUB})")
            else:
                results.append(f"  ❌ {ext_domain} CNAME 添加失败")
        except Exception as e:
            results.append(f"  ❌ {ext_domain}: 处理异常 - {e}")

    # 生成报告
    usage_report = "\n".join([f"  {sub}.{DOMAIN} : {count}/{MAX_CNAME_PER_SUB}" for sub, count in sub_usage.items()])
    report_lines = [
        f"<b>外部域名 CNAME 处理报告</b>",
        f"目标根域名: {DOMAIN}",
        f"优选子域名限额（每个最多 {MAX_CNAME_PER_SUB} 个域名）:",
        usage_report,
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "处理结果:"
    ] + results

    final_text = "\n".join(report_lines)
    print("\n" + final_text.replace("<b>", "").replace("</b>", ""))
    notifier.send_telegram(final_text)

if __name__ == "__main__":
    main()