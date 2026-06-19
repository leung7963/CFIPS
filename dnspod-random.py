#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare 优选 IP 生成器 + 腾讯云 DNS 更新 (固定子域名版本)
- 生成固定子域名：1-1-1, 1-1-2, 1-2-1, 1-2-2, 2-1-1, 2-1-2, 2-2-1, 2-2-2
- 每个子域名分配 2 个优选 IP（线路为“默认”）
- IPv4 可选段通过环境变量 ALLOWED_IPV4_PREFIXES 配置（默认为 104.26.,172.67.），
  现在代表“生成 IP 的前缀”而非 CIDR 前缀。
- 已移除 IPv6 支持
- 包含 Telegram 通知
"""

import os
import sys
import time
import random
import json
import hashlib
import hmac
import ipaddress
import requests
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== 环境变量读取 ==========
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY")
DOMAIN = os.environ.get("DOMAIN")

# 固定子域名及每条记录的 IP 数量
SUB_DOMAINS = ['1-1-1', '1-1-2', '1-2-1', '1-2-2', '2-1-1', '2-1-2', '2-2-1', '2-2-2']
IPS_PER_SUBDOMAIN = 2   # 每个子域名分配 2 个 IP

TEST_URL_TEMPLATE = os.environ.get("TEST_URL_TEMPLATE", "http://{ip}:443/")
EXPECTED_STATUS_CODE = int(os.environ.get("EXPECTED_STATUS_CODE", "400"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "5"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "500"))
ATTEMPT_MULTIPLIER = int(os.environ.get("ATTEMPT_MULTIPLIER", "10000"))

# 允许的 IPv4 段 —— 现在代表“生成的 IP 地址的前缀”，例如 "104.26." 会匹配 104.26.x.x
ALLOWED_IPV4_PREFIXES = [
    p.strip() for p in os.environ.get("ALLOWED_IPV4_PREFIXES", "104.26.,172.67.").split(",") if p.strip()
]

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# 计算所需 IP 总数（仅 IPv4）
NEEDED_IPV4 = len(SUB_DOMAINS) * IPS_PER_SUBDOMAIN

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
    canonical_request = "\n".join([http_method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, hashed_payload])
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
    headers = {"Authorization": authorization, "Content-Type": ct, "Host": "dnspod.tencentcloudapi.com", "X-TC-Action": action, "X-TC-Version": version, "X-TC-Timestamp": str(timestamp), "X-TC-Region": region}
    return headers, payload_str

# ========== IP 管理类 ==========
class CloudflareIPManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CF-Optimizer/1.0'})
        self._ipv4_cidrs = []

    def fetch_cloudflare_ips(self) -> bool:
        """获取 Cloudflare 所有 IPv4 CIDR 列表（不过滤，全部保留）"""
        try:
            response = self.session.get(CF_IPV4_URL, timeout=15)
            response.raise_for_status()
            raw_ipv4_cidrs = [line.strip() for line in response.text.splitlines() if line.strip()]
        except Exception as e:
            print(f"获取 IPv4 CIDR 失败: {e}")
            return False

        self._ipv4_cidrs = raw_ipv4_cidrs  # 保留全部 CIDR，不再按前缀筛选
        print(f"获取到 {len(self._ipv4_cidrs)} 个 Cloudflare IPv4 段")
        return bool(self._ipv4_cidrs)

    def _ip_matches_allowed_prefix(self, ip: str) -> bool:
        """检查 IP 是否以允许的前缀开头，若未配置前缀则全部通过"""
        if not ALLOWED_IPV4_PREFIXES:
            return True
        return any(ip.startswith(prefix) for prefix in ALLOWED_IPV4_PREFIXES)

    def generate_random_ip_from_cidr(self, cidr: str) -> Optional[str]:
        """从 CIDR 中随机生成一个 IPv4 地址"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            net_int, bcast_int = int(network.network_address), int(network.broadcast_address)
            start, end = (net_int + 1, bcast_int - 1) if network.prefixlen <= 30 else (net_int, bcast_int)
            if start <= end:
                return str(ipaddress.ip_address(random.randint(start, end)))
        except:
            pass
        return None

    def test_ip_worker(self, ip_address: str) -> Tuple[str, bool, int]:
        try:
            url = TEST_URL_TEMPLATE.format(ip=ip_address)
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=False)
            return ip_address, (resp.status_code == EXPECTED_STATUS_CODE), resp.status_code
        except:
            return ip_address, False, 0

    def generate_and_test_ips_concurrent(self, num_ips: int) -> List[str]:
        """生成并测试指定数量的优质 IPv4，仅保留符合 IP 前缀的地址"""
        if num_ips <= 0:
            return []
        qualified_ips, attempted_ips = [], set()
        max_attempts = num_ips * ATTEMPT_MULTIPLIER

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_ip = {}

            def submit():
                nonlocal max_attempts
                if max_attempts <= 0:
                    return False
                for _ in range(10):
                    ip = self.generate_random_ip_from_cidr(random.choice(self._ipv4_cidrs))
                    if ip and ip not in attempted_ips:
                        attempted_ips.add(ip)
                        max_attempts -= 1
                        # 只测试符合 IP 前缀的地址
                        if self._ip_matches_allowed_prefix(ip):
                            future_to_ip[executor.submit(self.test_ip_worker, ip)] = ip
                            return True
                return False

            # 初始填充任务
            for _ in range(min(MAX_WORKERS * 2, max_attempts)):
                submit()

            while future_to_ip and len(qualified_ips) < num_ips:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip.pop(future)
                    try:
                        res_ip, ok, _ = future.result()
                        if ok and res_ip not in qualified_ips:
                            qualified_ips.append(res_ip)
                            print(f"✓ 已找到 {len(qualified_ips)}/{num_ips}: {res_ip}")
                    except:
                        pass
                    if len(qualified_ips) < num_ips:
                        submit()
                    else:
                        break
        return qualified_ips

# ========== DNS & 通知类 ==========
class TencentDNSManager:
    def __init__(self, secret_id: str, secret_key: str):
        self.secret_id, self.secret_key = secret_id, secret_key
        self.session = requests.Session()

    def _call_api(self, action: str, payload: dict) -> dict:
        headers, body = sign_v3("dnspod", action, "2021-03-23", payload, self.secret_id, self.secret_key)
        resp = self.session.post("https://dnspod.tencentcloudapi.com", headers=headers, data=body, timeout=10)
        return resp.json()

    def delete_records_by_subdomain_and_type(self, domain: str, sub: str, record_type: str):
        list_resp = self._call_api("DescribeRecordList", {"Domain": domain, "Subdomain": sub})
        records = list_resp.get("Response", {}).get("RecordList", [])
        for r in records:
            if r.get("Name") == sub and r.get("Type") == record_type:
                self._call_api("DeleteRecord", {"Domain": domain, "RecordId": r.get("RecordId")})

    def add_record(self, domain: str, sub: str, record_type: str, line: str, value: str, weight: int = 1):
        payload = {"Domain": domain, "SubDomain": sub, "RecordType": record_type, "RecordLine": line, "Value": value, "TTL": 600, "Weight": weight}
        self._call_api("CreateRecord", payload)

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

# ========== 分配逻辑 ==========
def distribute_to_subdomains(ip_pool: List[str]) -> Dict[str, List[str]]:
    """将 IP 池按顺序分配给各子域名，每个子域名 IPS_PER_SUBDOMAIN 个"""
    result = {sub: [] for sub in SUB_DOMAINS}
    if not ip_pool:
        return result
    idx = 0
    for sub in SUB_DOMAINS:
        result[sub] = ip_pool[idx:idx + IPS_PER_SUBDOMAIN]
        idx += IPS_PER_SUBDOMAIN
    return result

# ========== 主程序 ==========
def main():
    requests.packages.urllib3.disable_warnings()
    ipv4_desc = "、".join(ALLOWED_IPV4_PREFIXES) if ALLOWED_IPV4_PREFIXES else "全部"
    print("=" * 60)
    print("Cloudflare 优选 IP 生成器 (仅 IPv4)")
    print(f"子域名列表: {SUB_DOMAINS} | 每个子域名 {IPS_PER_SUBDOMAIN} 个 IP")
    print(f"IP 前缀限制: {ipv4_desc} 开头（基于生成的 IP 地址筛选）")
    print("=" * 60)

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY or not DOMAIN:
        print("错误：缺少必要环境变量")
        sys.exit(1)

    ip_manager = CloudflareIPManager()
    dns_manager = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    if not ip_manager.fetch_cloudflare_ips():
        sys.exit(1)

    print(f"需要 IPv4 数量: {NEEDED_IPV4}")

    ipv4_pool = ip_manager.generate_and_test_ips_concurrent(NEEDED_IPV4)

    report = [
        f"<b>Cloudflare 优选报告 (仅 IPv4)</b>",
        f"域名: {DOMAIN}",
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"IP 前缀: {ipv4_desc}",
        f""
    ]

    # 处理 IPv4
    v4_status = "未生成"
    v4_details = ""
    if NEEDED_IPV4 > 0:
        if len(ipv4_pool) >= NEEDED_IPV4:
            for sub in SUB_DOMAINS:
                dns_manager.delete_records_by_subdomain_and_type(DOMAIN, sub, 'A')
            dist = distribute_to_subdomains(ipv4_pool)
            for sub, ips in dist.items():
                for ip in ips:
                    dns_manager.add_record(DOMAIN, sub, 'A', '默认', ip)
                v4_details += f"\n  {sub}.{DOMAIN} → {', '.join(ips)}"
            v4_status = f"✅ 更新成功 ({len(ipv4_pool)} 个 IP)"
        else:
            v4_status = f"❌ 数量不足 ({len(ipv4_pool)}/{NEEDED_IPV4})，已跳过"

    report.append(f"IPv4: {v4_status}{v4_details}")

    final_text = "\n".join(report)
    print("\n" + final_text.replace("<b>","").replace("</b>",""))
    notifier.send_telegram(final_text)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"未捕获异常: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)