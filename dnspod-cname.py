#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
将你腾讯云域名下的指定子域名 CNAME 到随机挑选的两个全 Cloudflare 域名
- 从外部 URL 获取域名列表，并发检测其 A 记录是否全部属于 CF
- 随机选取两个全 CF 域名作为 CNAME 目标
- 先删除子域名所有旧记录，再添加 CNAME
- 配置通过环境变量传入
"""

import os
import sys
import socket
import ipaddress
import hashlib
import hmac
import time
import json
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ========== 环境变量配置（全部可配） ==========
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID", "")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY", "")

# 你自己的域名（逗号分隔）
MY_DOMAINS_STR = os.environ.get("MY_DOMAINS", "")
MY_DOMAINS = [d.strip() for d in MY_DOMAINS_STR.split(",") if d.strip()] if MY_DOMAINS_STR else []

# 子域名列表（逗号分隔）
SUB_DOMAINS_STR = os.environ.get("SUB_DOMAINS", "1-1,1-2,2-1,2-2")
SUB_DOMAINS = [s.strip() for s in SUB_DOMAINS_STR.split(",") if s.strip()]

# CNAME 目标选择模式
AUTO_PICK = os.environ.get("AUTO_PICK_CF_TARGETS", "True").lower() in ("true", "1", "yes")
MANUAL_TARGETS_STR = os.environ.get("MANUAL_CF_TARGETS", "")
MANUAL_CF_TARGETS = [t.strip() for t in MANUAL_TARGETS_STR.split(",") if t.strip()] if MANUAL_TARGETS_STR else []

# 是否真实更新 DNS
DO_UPDATE = os.environ.get("DO_UPDATE", "False").lower() in ("true", "1", "yes")

# 外部域名列表 URL
EXTERNAL_DOMAINS_URL = os.environ.get(
    "EXTERNAL_DOMAINS_URL",
    "https://raw.githubusercontent.com/leung7963/CFIPS/main/domain.js"
)

# DNS 超时
DNS_TIMEOUT = int(os.environ.get("DNS_TIMEOUT", "5"))
socket.setdefaulttimeout(DNS_TIMEOUT)

CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4'


# ========== 以下为功能函数 ==========
def get_domains_from_url(url):
    """读取域名列表（每行一个域名，去重）"""
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    domains = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        domains.append(line)
    seen = set()
    unique = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


def get_cloudflare_ipv4_networks():
    """获取 Cloudflare IPv4 地址段"""
    resp = requests.get(CF_IPV4_URL, timeout=15)
    resp.raise_for_status()
    nets = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if line:
            nets.append(ipaddress.IPv4Network(line))
    return nets


def resolve_a(domain):
    """解析域名的 A 记录，返回 IPv4 集合"""
    try:
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
        return {addr[4][0] for addr in addrinfo}
    except socket.gaierror:
        return None


def check_domain(domain, cf_networks):
    """检查域名的 A 记录是否全部属于 Cloudflare"""
    ips = resolve_a(domain)
    if ips is None:
        return {'domain': domain, 'ips': [], 'is_all_cf': False, 'error': 'DNS resolve failed'}
    cf_ips = []
    non_cf = []
    for ip_str in ips:
        ip = ipaddress.IPv4Address(ip_str)
        if any(ip in net for net in cf_networks):
            cf_ips.append(ip_str)
        else:
            non_cf.append(ip_str)
    is_all_cf = len(non_cf) == 0 and len(cf_ips) > 0
    return {
        'domain': domain,
        'ips': sorted(ips),
        'cf_ips': sorted(cf_ips),
        'non_cf_ips': sorted(non_cf),
        'is_all_cf': is_all_cf,
        'error': None
    }


def dnspod_api_call(action, params, secret_id, secret_key):
    """腾讯云 DNSPod API 签名 V3"""
    endpoint = 'dnspod.tencentcloudapi.com'
    service = 'dnspod'
    host = endpoint
    algorithm = 'TC3-HMAC-SHA256'
    timestamp = int(time.time())
    date = time.strftime('%Y-%m-%d', time.gmtime(timestamp))

    http_request_method = 'POST'
    canonical_uri = '/'
    canonical_querystring = ''
    ct = 'application/json; charset=utf-8'
    payload = json.dumps(params)
    canonical_headers = f'content-type:{ct}\nhost:{host}\n'
    signed_headers = 'content-type;host'
    hashed_request_payload = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    canonical_request = (http_request_method + '\n' +
                         canonical_uri + '\n' +
                         canonical_querystring + '\n' +
                         canonical_headers + '\n' +
                         signed_headers + '\n' +
                         hashed_request_payload)

    credential_scope = f'{date}/{service}/tc3_request'
    hashed_canonical_request = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    string_to_sign = (algorithm + '\n' +
                      str(timestamp) + '\n' +
                      credential_scope + '\n' +
                      hashed_canonical_request)

    def sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    secret_date = sign(('TC3' + secret_key).encode('utf-8'), date)
    secret_service = sign(secret_date, service)
    secret_signing = sign(secret_service, 'tc3_request')
    signature = hmac.new(secret_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    authorization = (algorithm + ' ' +
                     'Credential=' + secret_id + '/' + credential_scope + ', ' +
                     'SignedHeaders=' + signed_headers + ', ' +
                     'Signature=' + signature)

    headers = {
        'Authorization': authorization,
        'Content-Type': ct,
        'Host': host,
        'X-TC-Action': action,
        'X-TC-Timestamp': str(timestamp),
        'X-TC-Version': '2021-03-23'
    }

    resp = requests.post(f'https://{host}', headers=headers, data=payload)
    return resp.json()


def delete_all_records_for_subdomain(mydomain, sub_domain, secret_id, secret_key):
    """删除指定子域名的全部解析记录"""
    params = {
        'Domain': mydomain,
        'Subdomain': sub_domain
    }
    resp = dnspod_api_call('DescribeRecordList', params, secret_id, secret_key)
    records = resp.get('Response', {}).get('RecordList', [])
    if not records:
        return 0
    count = 0
    for rec in records:
        del_resp = dnspod_api_call('DeleteRecord', {
            'Domain': mydomain,
            'RecordId': rec['RecordId']
        }, secret_id, secret_key)
        if 'Error' not in del_resp.get('Response', {}):
            print(f"    🗑 已删除 {rec['Name']}.{mydomain} 类型:{rec['Type']} -> {rec.get('Value', '')}")
            count += 1
        else:
            print(f"    ❌ 删除 {rec['Name']}.{mydomain} 失败: {del_resp}")
    return count


def ensure_cname_records(mydomain, sub_domain, cname_targets, secret_id, secret_key):
    """先删除子域名所有旧记录，再添加 CNAME 到每个目标"""
    print(f"  🧹 清除 {sub_domain}.{mydomain} 的现有记录...")
    deleted = delete_all_records_for_subdomain(mydomain, sub_domain, secret_id, secret_key)
    print(f"  ✅ 共清除 {deleted} 条记录")

    if not cname_targets:
        print(f"  ⚠️ 没有 CNAME 目标，跳过添加")
        return

    print(f"  ➕ 添加 CNAME 记录指向: {cname_targets}")
    for target in cname_targets:
        create_params = {
            'Domain': mydomain,
            'SubDomain': sub_domain,
            'RecordType': 'CNAME',
            'RecordLine': '默认',
            'Value': target,
            'TTL': 600
        }
        create_resp = dnspod_api_call('CreateRecord', create_params, secret_id, secret_key)
        if 'Response' in create_resp and 'Error' not in create_resp['Response']:
            print(f"    ✅ 已创建 {sub_domain}.{mydomain} CNAME -> {target}")
        else:
            print(f"    ❌ 创建 {sub_domain}.{mydomain} CNAME -> {target} 失败: {create_resp}")


def main():
    # 必要检查
    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY:
        print("❌ 请设置环境变量 TENCENT_SECRET_ID 和 TENCENT_SECRET_KEY")
        sys.exit(1)
    if not MY_DOMAINS:
        print("❌ 请设置环境变量 MY_DOMAINS（你的腾讯云域名，逗号分隔）")
        sys.exit(1)
    if not SUB_DOMAINS:
        print("❌ 子域名列表为空，请设置 SUB_DOMAINS")
        sys.exit(1)

    # ---------- 第一步：检测 CF 域名 ----------
    print("🔍 正在获取待检测域名列表...")
    all_domains = get_domains_from_url(EXTERNAL_DOMAINS_URL)
    print(f"✅ 共获取 {len(all_domains)} 个域名\n")

    print("🌐 正在获取 Cloudflare IPv4 范围...")
    cf_networks = get_cloudflare_ipv4_networks()
    print(f"✅ 加载了 {len(cf_networks)} 个 CF IP 段\n")

    print("🚀 开始 DNS 检测 (仅 A 记录)...")
    results = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(check_domain, d, cf_networks): d for d in all_domains}
        for future in as_completed(future_to_domain):
            res = future.result()
            results.append(res)
            ips_str = ', '.join(res['ips']) if res['ips'] else 'N/A'
            status = '✅ CF' if res['is_all_cf'] else ('❌ 解析失败' if res['error'] else '❌ 非CF')
            print(f"  {res['domain']:40s}  {ips_str:30s}  {status}")

    cf_domains = [r['domain'] for r in results if r['is_all_cf']]
    print(f"\n📊 检测完毕：完全在 CF 上的域名共 {len(cf_domains)} 个")
    if cf_domains:
        for d in cf_domains:
            print(f"  - {d}")

    if not cf_domains:
        print("❌ 没有找到任何 CF 域名，无法设置 CNAME，退出。")
        return

    # ---------- 第二步：确定 CNAME 目标 ----------
    if AUTO_PICK:
        pick_count = min(2, len(cf_domains))
        cname_targets = random.sample(cf_domains, pick_count)
        print(f"\n🎲 随机选用 {pick_count} 个 CF 域名作为 CNAME 目标: {cname_targets}")
    else:
        cname_targets = MANUAL_CF_TARGETS
        if not cname_targets:
            print("❌ 手动模式但未提供 MANUAL_CF_TARGETS，退出。")
            return
        print(f"\n🎯 手动指定 CNAME 目标: {cname_targets}")

    # ---------- 第三步：为我方域名添加 CNAME ----------
    print(f"\n📋 你的腾讯云域名: {MY_DOMAINS}")
    print(f"📋 子域名: {SUB_DOMAINS}")
    print(f"📋 CNAME 目标: {cname_targets}")

    if not DO_UPDATE:
        print("\n⚠️  DO_UPDATE = False，仅展示模拟动作：")
        for mydomain in MY_DOMAINS:
            for sub in SUB_DOMAINS:
                print(f"    🧹 [模拟] 删除 {sub}.{mydomain} 的所有旧记录")
                for target in cname_targets:
                    print(f"    ➕ [模拟] 创建 {sub}.{mydomain} CNAME -> {target}")
        print("确认无误后，将环境变量 DO_UPDATE 设为 True 再次运行。")
        return

    # 真实执行
    print("\n🔨 开始修改 DNS 记录...")
    for mydomain in MY_DOMAINS:
        print(f"  🌍 处理你的域名: {mydomain}")
        for sub in SUB_DOMAINS:
            ensure_cname_records(mydomain, sub, cname_targets, TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    print("✅ 全部完成。")


if __name__ == '__main__':
    main()