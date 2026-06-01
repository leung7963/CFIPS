#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
外部域名 Cloudflare CNAME 工具（DNS 解析版）
- 从外部 URL 获取域名列表
- 先删除域名在腾讯云的原有全部记录
- 再通过 DNS 解析域名的 A 记录 IP
- 若 IP 属于 Cloudflare，则 CNAME 到优选子域名
- 每个优选子域名最多被 2 个外部域名指向（轮询分配）
- 支持 Telegram 通知
"""

import os
import sys
import time
import json
import hashlib
import hmac
import ipaddress
import socket
import requests
from typing import List, Dict, Tuple, Optional

# ========== 环境变量 ==========
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY")
DOMAIN = os.environ.get("DOMAIN")  # 优选子域名的根域名

SUB_DOMAINS = os.environ.get("SUB_DOMAINS", "1-1,1-2,2-1,2-2").split(",")
MAX_CNAME_PER_SUB = 2  # 每个优选子域名最多 2 个外部域名

EXTERNAL_DOMAINS_URL = os.environ.get(
    "EXTERNAL_DOMAINS_URL",
    "https://raw.githubusercontent.com/leung7963/CFIPS/main/domain.js"
)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ========== 腾讯云 API 签名 ==========
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

# ========== Cloudflare IP 检测 ==========
class CloudflareIPChecker:
    def __init__(self):
        self._ipv4_cidrs = []
        self._ipv6_cidrs = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'CF-CNAME-Tool/1.0'})

    def fetch_cidrs(self) -> bool:
        try:
            resp = self.session.get("https://www.cloudflare.com/ips-v4", timeout=15)
            resp.raise_for_status()
            self._ipv4_cidrs = [line.strip() for line in resp.text.splitlines() if line.strip()]
        except Exception as e:
            print(f"获取 IPv4 CIDR 失败: {e}")
            return False
        try:
            resp = self.session.get("https://www.cloudflare.com/ips-v6", timeout=15)
            resp.raise_for_status()
            self._ipv6_cidrs = [line.strip() for line in resp.text.splitlines() if line.strip()]
        except:
            pass
        return bool(self._ipv4_cidrs)

    def is_cloudflare_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv4Address):
                return any(ip in ipaddress.IPv4Network(c) for c in self._ipv4_cidrs)
            else:
                return any(ip in ipaddress.IPv6Network(c) for c in self._ipv6_cidrs)
        except:
            return False

# ========== DNS 解析 ==========
def dns_resolve_a(domain: str) -> Optional[str]:
    """解析域名的 A 记录，返回第一个 IPv4 地址，失败返回 None"""
    try:
        addrs = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for addr in addrs:
            ip = addr[4][0]
            if ipaddress.IPv4Address(ip):
                return ip
    except socket.gaierror:
        pass
    return None

# ========== 域名拆分（用于腾讯云 API） ==========
def split_domain(full_domain: str) -> Tuple[str, str]:
    """
    将完整域名拆分为腾讯云 API 所需的主域名和子域名
    例: example.com -> (example.com, @)
        www.example.com -> (example.com, www)
        a.b.example.com -> (example.com, a.b)
    """
    parts = full_domain.split(".")
    if len(parts) <= 2:
        return full_domain, "@"
    else:
        main_domain = ".".join(parts[-2:])
        sub_domain = ".".join(parts[:-2])
        return main_domain, sub_domain

# ========== 腾讯云 DNS 管理 ==========
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

    def _list_records(self, domain: str, sub: str) -> Optional[List[dict]]:
        """查询指定子域名的记录列表，失败返回 None"""
        payload = {"Domain": domain, "Subdomain": sub}
        resp = self._call_api("DescribeRecordList", payload)
        err = resp.get("Response", {}).get("Error")
        if err:
            print(f"  查询记录失败: {err.get('Message')}")
            return None
        return resp.get("Response", {}).get("RecordList", [])

    def delete_all_records(self, domain: str, sub: str):
        """删除指定子域名的所有记录"""
        print(f"  准备删除 {sub}.{domain} 的所有记录")
        records = self._list_records(domain, sub)
        if records is None:
            print("  无法获取记录列表，跳过删除")
            return
        for r in records:
            print(f"    删除: {r.get('Name')}.{domain} 类型:{r.get('Type')}")
            self._call_api("DeleteRecord", {"Domain": domain, "RecordId": r.get("RecordId")})

    def add_cname_record(self, domain: str, sub: str, target: str) -> bool:
        payload = {
            "Domain": domain,
            "SubDomain": sub,
            "RecordType": "CNAME",
            "RecordLine": "默认",
            "Value": target,
            "TTL": 600
        }
        resp = self._call_api("CreateRecord", payload)
        err = resp.get("Response", {}).get("Error")
        if err:
            print(f"    添加 CNAME 失败: {err.get('Message')}")
            return False
        print(f"    已添加 CNAME: {sub}.{domain} → {target}")
        return True

# ========== 通知 ==========
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
    print("外部域名 Cloudflare CNAME 工具 (DNS 解析版)")
    print(f"每个优选子域名最多 {MAX_CNAME_PER_SUB} 个域名")
    print("=" * 60)

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY or not DOMAIN:
        print("错误：缺少必要环境变量")
        sys.exit(1)

    cf_checker = CloudflareIPChecker()
    dns_mgr = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    if not cf_checker.fetch_cidrs():
        sys.exit(1)

    external_domains = fetch_external_domains(EXTERNAL_DOMAINS_URL)
    if not external_domains:
        print("未获取到任何外部域名")
        return

    print(f"\n获取到 {len(external_domains)} 个域名，开始处理...")
    sub_usage = {sub: 0 for sub in SUB_DOMAINS}
    results = []
    current_index = 0

    for full_domain in external_domains:
        print(f"\n处理域名: {full_domain}")
        try:
            # ---------- 第一步：拆分域名并删除腾讯云原有全部记录 ----------
            main_domain, sub_domain = split_domain(full_domain)
            print(f"  先删除 {full_domain} 在腾讯云的全部记录")
            dns_mgr.delete_all_records(main_domain, sub_domain)

            # ---------- 第二步：DNS 解析 A 记录 ----------
            ip = dns_resolve_a(full_domain)
            if ip is None:
                results.append(f"  {full_domain}: DNS 解析失败，无 A 记录，跳过")
                continue

            # ---------- 第三步：检查 IP 是否为 Cloudflare IP ----------
            if not cf_checker.is_cloudflare_ip(ip):
                results.append(f"  ⚠️ {full_domain}: IP {ip} 不是 Cloudflare IP，跳过")
                continue

            # ---------- 第四步：分配优选子域名并添加 CNAME ----------
            target_sub = None
            for i in range(len(SUB_DOMAINS)):
                idx = (current_index + i) % len(SUB_DOMAINS)
                if sub_usage[SUB_DOMAINS[idx]] < MAX_CNAME_PER_SUB:
                    target_sub = SUB_DOMAINS[idx]
                    current_index = (idx + 1) % len(SUB_DOMAINS)
                    break

            if target_sub is None:
                results.append(f"  ❌ {full_domain}: 优选子域名配额已满，跳过")
                continue

            cname_target = f"{target_sub}.{DOMAIN}."
            success = dns_mgr.add_cname_record(main_domain, sub_domain, cname_target)

            if success:
                sub_usage[target_sub] += 1
                results.append(f"  ✅ {full_domain} → CNAME {cname_target} (子域名 {target_sub} 已用 {sub_usage[target_sub]}/{MAX_CNAME_PER_SUB})")
            else:
                results.append(f"  ❌ {full_domain} CNAME 添加失败")

        except Exception as e:
            results.append(f"  ❌ {full_domain}: 异常 - {e}")

    # 生成报告
    usage_report = "\n".join([f"  {sub}.{DOMAIN} : {count}/{MAX_CNAME_PER_SUB}" for sub, count in sub_usage.items()])
    report = [
        f"<b>外部域名 CNAME 处理报告</b>",
        f"目标根域名: {DOMAIN}",
        f"优选子域名使用情况:",
        usage_report,
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "处理结果:"
    ] + results

    final_text = "\n".join(report)
    print("\n" + final_text.replace("<b>", "").replace("</b>", ""))
    notifier.send_telegram(final_text)

if __name__ == "__main__":
    main()