#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
将你腾讯云域名下的每个子域名分配一个全 Cloudflare 域名作为 CNAME
- 从外部 URL 获取域名列表，检测 A 记录是否全部属于 CF
- 将可用 CF 域名按顺序为每个子域名分配一个（域名不重复）
- 先删除子域名所有旧记录，再添加 CNAME
- 支持 Telegram 通知（报告执行结果）
"""

import os
import sys
import socket
import ipaddress
import hashlib
import hmac
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ========== 环境变量配置 ==========
DOMAIN = os.environ.get("DOMAIN", "")                      # 你的主域名
SUB_DOMAINS_STR = os.environ.get("SUB_DOMAINS", "1-1,1-2,2-1,2-2")
SUB_DOMAINS = [s.strip() for s in SUB_DOMAINS_STR.split(",") if s.strip()]

TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID", "")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY", "")

EXTERNAL_DOMAINS_URL = os.environ.get(
    "EXTERNAL_DOMAINS_URL",
    "https://raw.githubusercontent.com/leung7963/CFIPS/main/domain.js"
)

DNS_TIMEOUT = int(os.environ.get("DNS_TIMEOUT", "5"))
socket.setdefaulttimeout(DNS_TIMEOUT)

CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4'

# Telegram 通知配置
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


# ========== 功能函数 ==========
def send_telegram(text):
    """发送 Telegram 消息（非阻塞，失败不影响主流程）"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"⚠️ Telegram 发送失败: {e}")


def get_domains_from_url(url):
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
    resp = requests.get(CF_IPV4_URL, timeout=15)
    resp.raise_for_status()
    nets = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if line:
            nets.append(ipaddress.IPv4Network(line))
    return nets


def resolve_a(domain):
    try:
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
        return {addr[4][0] for addr in addrinfo}
    except socket.gaierror:
        return None


def check_domain(domain, cf_networks):
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
    host = 'dnspod.tencentcloudapi.com'
    service = 'dnspod'
    algorithm = 'TC3-HMAC-SHA256'
    timestamp = int(time.time())
    date = time.strftime('%Y-%m-%d', time.gmtime(timestamp))

    http_method = 'POST'
    canonical_uri = '/'
    canonical_querystring = ''
    ct = 'application/json; charset=utf-8'
    payload = json.dumps(params)
    canonical_headers = f'content-type:{ct}\nhost:{host}\n'
    signed_headers = 'content-type;host'
    hashed_payload = hashlib.sha256(payload.encode('utf-8')).hexdigest()
    canonical_request = (http_method + '\n' +
                         canonical_uri + '\n' +
                         canonical_querystring + '\n' +
                         canonical_headers + '\n' +
                         signed_headers + '\n' +
                         hashed_payload)

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
    params = {'Domain': mydomain, 'Subdomain': sub_domain}
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
            count += 1
        else:
            print(f"    ❌ 删除 {rec['Name']}.{mydomain} 失败: {del_resp}")
    return count


def ensure_cname_records(mydomain, sub_domain, cname_targets, secret_id, secret_key):
    print(f"  🧹 清除 {sub_domain}.{mydomain} 的现有记录...")
    deleted = delete_all_records_for_subdomain(mydomain, sub_domain, secret_id, secret_key)
    print(f"  ✅ 共清除 {deleted} 条记录")

    added = 0
    if not cname_targets:
        print(f"  ⚠️ 没有 CNAME 目标，跳过添加")
        return {'deleted': deleted, 'added': 0, 'targets': []}

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
            added += 1
            print(f"    ✅ 已创建 {sub_domain}.{mydomain} CNAME -> {target}")
        else:
            print(f"    ❌ 创建 {sub_domain}.{mydomain} CNAME -> {target} 失败: {create_resp}")
    return {'deleted': deleted, 'added': added, 'targets': cname_targets}


def main():
    # 用于构建通知消息的日志列表
    log_lines = []

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY:
        print("❌ 请设置环境变量 TENCENT_SECRET_ID 和 TENCENT_SECRET_KEY")
        sys.exit(1)
    if not DOMAIN:
        print("❌ 请设置环境变量 DOMAIN（你的主域名）")
        sys.exit(1)
    if not SUB_DOMAINS:
        print("❌ 子域名列表为空，请设置 SUB_DOMAINS")
        sys.exit(1)

    # 检测 CF 域名
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
    log_lines.append(f"检测到 {len(cf_domains)} 个全 CF 域名")

    if not cf_domains:
        msg = "❌ 没有找到任何 CF 域名，无法设置 CNAME，退出。"
        print(msg)
        log_lines.append(msg)
        send_telegram("\n".join(log_lines))
        return

    # 按顺序为每个子域名分配一个 CNAME（域名不重复）
    targets_map = {}
    for i, sub in enumerate(SUB_DOMAINS):
        if i < len(cf_domains):
            targets_map[sub] = [cf_domains[i]]
        else:
            targets_map[sub] = []   # CF 域名不够，该子域名不设置 CNAME

    print(f"\n📋 按顺序为子域名分配 CNAME（每个子域名最多一个）：")
    log_lines.append("分配结果：")
    for sub, targets in targets_map.items():
        if targets:
            line = f"  {sub}.{DOMAIN} -> {targets[0]}"
        else:
            line = f"  {sub}.{DOMAIN} -> 无可用 CF 域名，跳过"
        print(line)
        log_lines.append(line)

    # 修改 DNS 记录
    print("\n🔨 开始修改 DNS 记录...")
    summary = []
    for sub in SUB_DOMAINS:
        targets = targets_map[sub]
        print(f"  🌍 处理子域名: {sub}.{DOMAIN}，目标: {targets}")
        res = ensure_cname_records(DOMAIN, sub, targets, TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
        summary.append(f"{sub}.{DOMAIN}: 删除 {res['deleted']} 条记录，添加 {res['added']} 条 CNAME")

    print("✅ 全部完成。")
    summary.insert(0, f"主域名: {DOMAIN}")
    summary.insert(0, f"执行时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    final_msg = "\n".join(log_lines + summary)
    send_telegram(final_msg)


if __name__ == '__main__':
    main()