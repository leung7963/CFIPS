#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare 优选 IP 生成器 + 腾讯云 DNS 更新
- 从 Cloudflare 官网动态获取 CIDR 列表
- 随机生成 IP 并进行高并发测试
- 分运营商线路（移动/联通/电信/境内）和默认线路添加 DNS 记录
- 安全机制：若 IP 数量不足，不删除旧记录，不进行更新
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
import traceback
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== 环境变量读取 ==========
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY")
DOMAIN = os.environ.get("DOMAIN")
RECORD_NAME = os.environ.get("RECORD_NAME", "@")

ISP_IP_COUNT = int(os.environ.get("ISP_IP_COUNT", "2"))
DEFAULT_IP_COUNT = int(os.environ.get("DEFAULT_IP_COUNT", "2"))

ISP_IP_COUNT_V6 = int(os.environ.get("ISP_IP_COUNT_V6", str(ISP_IP_COUNT)))
DEFAULT_IP_COUNT_V6 = int(os.environ.get("DEFAULT_IP_COUNT_V6", str(DEFAULT_IP_COUNT)))

TEST_URL_TEMPLATE = os.environ.get("TEST_URL_TEMPLATE", "http://{ip}/")
EXPECTED_STATUS_CODE = int(os.environ.get("EXPECTED_STATUS_CODE", "403"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "5"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "500"))
ATTEMPT_MULTIPLIER = int(os.environ.get("ATTEMPT_MULTIPLIER", "10000"))
GENERATE_IPV6 = os.environ.get("GENERATE_IPV6", "true").lower() == "true"

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPV6_URL = "https://www.cloudflare.com/ips-v6"

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ========== 常量 ==========
# 新增了 '境内' 线路
LINES = ['移动', '联通', '电信', '境内', '默认']


# ========== 腾讯云 API 签名函数 (保持不变) ==========
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

# ========== IP 管理类 (保持不变) ==========
class CloudflareIPManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self._ipv4_cidrs = []
        self._ipv6_cidrs = []

    def fetch_cloudflare_ips(self) -> bool:
        def get_cidrs(url: str, version: int) -> List[str]:
            try:
                response = self.session.get(url, timeout=15)
                response.raise_for_status()
                return [line.strip() for line in response.text.splitlines() if line.strip()]
            except Exception as e:
                print(f"获取 IPv{version} CIDR 失败: {e}")
                return []
        self._ipv4_cidrs = get_cidrs(CF_IPV4_URL, 4)
        if GENERATE_IPV6: self._ipv6_cidrs = get_cidrs(CF_IPV6_URL, 6)
        return bool(self._ipv4_cidrs)

    def generate_random_ip_from_cidr(self, cidr: str, is_ipv6: bool = False) -> Optional[str]:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            net_int, bcast_int = int(network.network_address), int(network.broadcast_address)
            start, end = (net_int + 1, bcast_int - 1) if network.prefixlen <= (126 if is_ipv6 else 30) else (net_int, bcast_int)
            return str(ipaddress.ip_address(random.randint(start, end))) if start <= end else None
        except: return None

    def test_ip_worker(self, ip_address: str) -> Tuple[str, bool, int]:
        try:
            url = TEST_URL_TEMPLATE.format(ip=f"[{ip_address}]" if ':' in ip_address else ip_address)
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=False)
            return ip_address, (resp.status_code == EXPECTED_STATUS_CODE), resp.status_code
        except: return ip_address, False, 0

    def generate_and_test_ips_concurrent(self, num_ips: int, is_ipv6: bool = False) -> List[str]:
        if num_ips <= 0: return []
        cidrs = self._ipv6_cidrs if is_ipv6 else self._ipv4_cidrs
        qualified_ips, attempted_ips = [], set()
        max_attempts = num_ips * ATTEMPT_MULTIPLIER
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_ip = {}
            def submit():
                nonlocal max_attempts
                if max_attempts <= 0: return False
                for _ in range(10):
                    ip = self.generate_random_ip_from_cidr(random.choice(cidrs), is_ipv6)
                    if ip and ip not in attempted_ips:
                        attempted_ips.add(ip)
                        max_attempts -= 1
                        future_to_ip[executor.submit(self.test_ip_worker, ip)] = ip
                        return True
                return False

            for _ in range(min(MAX_WORKERS * 2, max_attempts)): submit()
            while future_to_ip and len(qualified_ips) < num_ips:
                for future in as_completed(future_to_ip):
                    ip = future_to_ip.pop(future)
                    try:
                        res_ip, ok, _ = future.result()
                        if ok and res_ip not in qualified_ips:
                            qualified_ips.append(res_ip)
                            print(f"✓ Found {len(qualified_ips)}/{num_ips}: {res_ip}")
                    except: pass
                    if len(qualified_ips) < num_ips: submit()
                    else: break
        return qualified_ips

# ========== DNS & 通知类 (保持不变) ==========
class TencentDNSManager:
    def __init__(self, secret_id: str, secret_key: str):
        self.secret_id, self.secret_key = secret_id, secret_key
        self.session = requests.Session()

    def _call_api(self, action: str, payload: dict) -> dict:
        headers, body = sign_v3("dnspod", action, "2021-03-23", payload, self.secret_id, self.secret_key)
        resp = self.session.post("https://dnspod.tencentcloudapi.com", headers=headers, data=body, timeout=10)
        return resp.json()

    def delete_records_by_type(self, domain: str, sub: str, record_type: str):
        list_resp = self._call_api("DescribeRecordList", {"Domain": domain, "Subdomain": sub})
        records = list_resp.get("Response", {}).get("RecordList", [])
        for r in records:
            if r.get("Name") == sub and r.get("Type") == record_type:
                self._call_api("DeleteRecord", {"Domain": domain, "RecordId": r.get("RecordId")})

    def add_record(self, domain: str, sub: str, record_type: str, line: str, value: str, weight: int = 1):
        payload = {"Domain": domain, "SubDomain": sub, "RecordType": record_type, "RecordLine": line, "Value": value, "TTL": 600, "Weight": weight}
        self._call_api("CreateRecord", payload)

# ========== 核心修改点：IP 分配与主逻辑 ==========

def distribute_ips(ip_pool: List[str], isp_count: int, default_count: int) -> Dict[str, List[str]]:
    """
    更新：加入了 '境内' 线路分配逻辑
    """
    result = {line: [] for line in LINES}
    if not ip_pool: return result

    # 包含 移动、联通、电信、境内 + 默认
    total_needed = isp_count * 4 + default_count 
    pool_size = len(ip_pool)
    extended = [ip_pool[i % pool_size] for i in range(total_needed)]
    
    idx = 0
    # 分配运营商和境内线路
    for line in ['移动', '联通', '电信', '境内']:
        result[line] = extended[idx:idx + isp_count]
        idx += isp_count
    # 分配默认
    result['默认'] = extended[idx:idx + default_count]
    return result

def main():
    requests.packages.urllib3.disable_warnings()
    print("=" * 60)
    print("Cloudflare 优选 IP (境内线路支持 + 数量安全检查版)")
    print("=" * 60)

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY or not DOMAIN:
        print("错误：缺少环境变量")
        sys.exit(1)

    ip_manager = CloudflareIPManager()
    dns_manager = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)

    if not ip_manager.fetch_cloudflare_ips():
        sys.exit(1)

    # 目标数量：4个ISP线路 + 1个默认线路
    needed_v4 = ISP_IP_COUNT * 4 + DEFAULT_IP_COUNT
    needed_v6 = (ISP_IP_COUNT_V6 * 4 + DEFAULT_IP_COUNT_V6) if GENERATE_IPV6 else 0

    ipv4_pool = ip_manager.generate_and_test_ips_concurrent(needed_v4, is_ipv6=False)
    ipv6_pool = ip_manager.generate_and_test_ips_concurrent(needed_v6, is_ipv6=True) if GENERATE_IPV6 else []

    # --- 处理 IPv4 更新 ---
    if len(ipv4_pool) >= needed_v4:
        print(f"\n[IPv4] 找到 {len(ipv4_pool)} 个 IP，达到目标 {needed_v4}，开始更新...")
        dns_manager.delete_records_by_type(DOMAIN, RECORD_NAME, 'A')
        dist = distribute_ips(ipv4_pool, ISP_IP_COUNT, DEFAULT_IP_COUNT)
        for line, ips in dist.items():
            for ip in ips:
                dns_manager.add_record(DOMAIN, RECORD_NAME, 'A', line, ip)
    else:
        print(f"\n[IPv4] 警告：仅找到 {len(ipv4_pool)}/{needed_v4}，为了防止断连，跳过删除和更新！")

    # --- 处理 IPv6 更新 ---
    if GENERATE_IPV6:
        if len(ipv6_pool) >= needed_v6:
            print(f"\n[IPv6] 找到 {len(ipv6_pool)} 个 IP，达到目标 {needed_v6}，开始更新...")
            dns_manager.delete_records_by_type(DOMAIN, RECORD_NAME, 'AAAA')
            dist = distribute_ips(ipv6_pool, ISP_IP_COUNT_V6, DEFAULT_IP_COUNT_V6)
            for line, ips in dist.items():
                for ip in ips:
                    dns_manager.add_record(DOMAIN, RECORD_NAME, 'AAAA', line, ip)
        else:
            print(f"\n[IPv6] 警告：仅找到 {len(ipv6_pool)}/{needed_v6}，跳过更新！")

    print("\n任务结束。")

if __name__ == "__main__":
    main()