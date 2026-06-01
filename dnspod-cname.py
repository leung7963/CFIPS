#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
外部域名 Cloudflare CNAME 工具
- 从外部 URL 获取域名列表
- 检测每个域名的 A 记录 IP 是否属于 Cloudflare
- 若属于 Cloudflare IP，则删除原 A 记录，添加 CNAME 到指定优选子域名（轮询分配）
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

# ========== Cloudflare IP 检测类（仅保留 CIDR 获取与判断） ==========
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
            # 也可排除某些段，如按需过滤
        except Exception as e:
            print(f"获取 IPv4 CIDR 失败: {e}")
            return False

        try:
            resp_v6 = self.session.get("https://www.cloudflare.com/ips-v6", timeout=15)
            resp_v6.raise_for_status()
            self._ipv6_cidrs = [line.strip() for line in resp_v6.text.splitlines() if line.strip()]
        except Exception as e:
            print(f"获取 IPv6 CIDR 失败: {e}")
            # 非致命，可能只用 IPv4

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

    def delete_records_by_type(self, domain: str, sub: str, record_type: str):
        """删除指定类型的所有记录（避免冲突）"""
        list_resp = self._call_api("DescribeRecordList", {"Domain": domain, "Subdomain": sub})
        records = list_resp.get("Response", {}).get("RecordList", [])
        for r in records:
            if r.get("Type") == record_type:
                self._call_api("DeleteRecord", {"Domain": domain, "RecordId": r.get("RecordId")})
                print(f"  已删除 {record_type} 记录: {r.get('Name')}.{domain}")

    def add_cname_record(self, domain: str, sub: str, target: str, line: str = "默认"):
        """添加 CNAME 记录"""
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
    """从 URL 获取域名列表，每行一个，去重并过滤空行"""
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        lines = [line.strip().lower() for line in resp.text.splitlines() if line.strip()]
        # 基本格式过滤：至少包含一个点
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
    print("=" * 60)

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY or not DOMAIN:
        print("错误：缺少必要环境变量 TENCENT_SECRET_ID / TENCENT_SECRET_KEY / DOMAIN")
        sys.exit(1)

    # 初始化
    cf_checker = CloudflareIPChecker()
    dns_mgr = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    # 获取 Cloudflare IP 范围（用于后续判断）
    if not cf_checker.fetch_cidrs():
        print("无法获取 Cloudflare IP 范围，退出。")
        sys.exit(1)

    # 获取外部域名列表
    external_domains = fetch_external_domains(EXTERNAL_DOMAINS_URL)
    if not external_domains:
        print("未获取到任何外部域名，退出。")
        return

    print(f"获取到 {len(external_domains)} 个外部域名，开始检测并设置 CNAME...")

    # 处理结果记录
    results = []
    subdomain_cycle = 0  # 轮询索引

    for ext_domain in external_domains:
        print(f"\n处理域名: {ext_domain}")
        try:
            # 1. 获取该域名的 A 记录（@ 记录）
            a_records = dns_mgr.get_a_records(ext_domain, sub="@")
            if not a_records:
                results.append(f"  {ext_domain}: 无 A 记录，跳过")
                continue

            # 2. 检查第一个 A 记录的 IP 是否属于 Cloudflare
            first_ip = a_records[0].get("Value", "")
            if not first_ip:
                results.append(f"  {ext_domain}: A 记录无 IP 值，跳过")
                continue

            if cf_checker.is_cloudflare_ip(first_ip):
                # 3. 删除原有 A 记录
                dns_mgr.delete_records_by_type(ext_domain, "@", "A")
                # 4. 选择轮询的优选子域名
                target_sub = SUB_DOMAINS[subdomain_cycle % len(SUB_DOMAINS)]
                subdomain_cycle += 1
                cname_target = f"{target_sub}.{DOMAIN}."
                # 5. 添加 CNAME 记录
                success = dns_mgr.add_cname_record(ext_domain, "@", cname_target)
                if success:
                    results.append(f"  ✅ {ext_domain} → CNAME {cname_target}")
                else:
                    results.append(f"  ❌ {ext_domain} CNAME 添加失败")
            else:
                results.append(f"  ⚠️ {ext_domain}: IP {first_ip} 不是 Cloudflare IP，跳过")
        except Exception as e:
            results.append(f"  ❌ {ext_domain}: 处理异常 - {e}")

    # 生成报告
    report_lines = [
        f"<b>外部域名 CNAME 处理报告</b>",
        f"目标根域名: {DOMAIN}",
        f"优选子域名: {', '.join(SUB_DOMAINS)}",
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "处理结果:"
    ] + results

    final_text = "\n".join(report_lines)
    print("\n" + final_text.replace("<b>", "").replace("</b>", ""))
    notifier.send_telegram(final_text)

if __name__ == "__main__":
    main()