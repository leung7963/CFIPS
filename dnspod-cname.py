import socket
import ipaddress
import hashlib
import hmac
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

import requests

# ==================== 配置区（必须填写） ====================
TENCENT_SECRET_ID = ''          # 腾讯云 SecretId
TENCENT_SECRET_KEY = ''         # 腾讯云 SecretKey

# 需要添加 CNAME 的子域名列表（示例：1-1, 1-2, 2-1, 2-2）
SUB_DOMAINS = ['1-1', '1-2', '2-1', '2-2']

# 腾讯云目标 CNAME 地址（可填写多个，每个子域名会逐一创建指向这些目标的记录）
CNAME_TARGETS = [
    'target1.cdn.dnsv1.com',    # 第一个 CNAME 目标
    'target2.cdn.dnsv1.com'     # 第二个 CNAME 目标（如不需要可删除）
]

# 是否真正执行 API 修改（建议先设为 False 测试）
DO_UPDATE = False
# ==========================================================

DNS_TIMEOUT = 5
socket.setdefaulttimeout(DNS_TIMEOUT)

CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4'
DOMAIN_LIST_URL = 'https://raw.githubusercontent.com/leung7963/CFIPS/main/domain.js'


def get_domains_from_url(url):
    """从 URL 读取域名列表（每行一个域名）"""
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    domains = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        domains.append(line)
    seen = set()
    unique_domains = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)
    return unique_domains


def get_cloudflare_ipv4_networks():
    """获取 Cloudflare IPv4 地址段"""
    resp = requests.get(CF_IPV4_URL, timeout=15)
    resp.raise_for_status()
    networks = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if line:
            networks.append(ipaddress.IPv4Network(line))
    return networks


def resolve_a(domain):
    """解析 A 记录，返回 IPv4 集合"""
    try:
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
        return {addr[4][0] for addr in addrinfo}
    except socket.gaierror:
        return None


def check_domain(domain, cf_networks):
    """检查域名 A 记录是否全属于 CF"""
    ips = resolve_a(domain)
    if ips is None:
        return {'domain': domain, 'ips': [], 'cf_ips': [], 'non_cf_ips': [],
                'is_all_cf': False, 'error': 'DNS resolve failed'}

    cf_ips = []
    non_cf_ips = []
    for ip_str in ips:
        ip_addr = ipaddress.IPv4Address(ip_str)
        if any(ip_addr in net for net in cf_networks):
            cf_ips.append(ip_str)
        else:
            non_cf_ips.append(ip_str)

    is_all_cf = len(non_cf_ips) == 0 and len(cf_ips) > 0
    return {
        'domain': domain,
        'ips': sorted(ips),
        'cf_ips': sorted(cf_ips),
        'non_cf_ips': sorted(non_cf_ips),
        'is_all_cf': is_all_cf,
        'error': None
    }


def dnspod_api_call(action, params, secret_id, secret_key):
    """调用腾讯云 DNSPod API (签名 V3)"""
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


def ensure_cname_records(domain, sub_domain, cname_targets, secret_id, secret_key):
    """
    为指定域名和子域名，确保每条 CNAME 目标都有对应记录。
    如果目标值已存在则跳过，否则创建新记录。
    """
    # 1. 获取 DomainId
    list_params = {'Offset': 0, 'Limit': 100}
    resp = dnspod_api_call('DescribeDomainList', list_params, secret_id, secret_key)
    domain_id = None
    if 'Response' in resp and 'DomainList' in resp['Response']:
        for d in resp['Response']['DomainList']:
            if d['Name'] == domain:
                domain_id = d['DomainId']
                break
    if not domain_id:
        print(f"    ⚠️ 域名 {domain} 未在 DNSPod 中找到，跳过")
        return

    # 2. 查询该子域名的所有 CNAME 记录
    record_params = {
        'Domain': domain,
        'Subdomain': sub_domain,
        'RecordType': 'CNAME',
    }
    resp = dnspod_api_call('DescribeRecordList', record_params, secret_id, secret_key)
    existing_values = set()
    if 'Response' in resp and 'RecordList' in resp['Response']:
        for rec in resp['Response']['RecordList']:
            if rec['Name'] == sub_domain and rec['Type'] == 'CNAME':
                existing_values.add(rec['Value'])

    # 3. 对每个目标值，若缺失则创建
    for target in cname_targets:
        if target in existing_values:
            print(f"    ✅ {sub_domain}.{domain} -> {target} 已存在，跳过")
            continue
        create_params = {
            'Domain': domain,
            'SubDomain': sub_domain,
            'RecordType': 'CNAME',
            'RecordLine': '默认',
            'Value': target,
            'TTL': 600
        }
        create_resp = dnspod_api_call('CreateRecord', create_params, secret_id, secret_key)
        if 'Response' in create_resp and 'Error' not in create_resp['Response']:
            print(f"    ✅ 已创建 {sub_domain}.{domain} -> {target}")
        else:
            print(f"    ❌ 创建 {sub_domain}.{domain} -> {target} 失败: {create_resp}")


def main():
    # 1. 检测 Cloudflare 域名
    print("🔍 正在获取域名列表...")
    domains = get_domains_from_url(DOMAIN_LIST_URL)
    print(f"✅ 获取到 {len(domains)} 个域名\n")

    print("🌐 正在获取 Cloudflare IPv4 范围...")
    cf_networks = get_cloudflare_ipv4_networks()
    print(f"✅ 加载了 {len(cf_networks)} 个 CF IPv4 段\n")

    results = []
    print("🚀 开始 DNS 检测 (仅 A 记录)...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {executor.submit(check_domain, d, cf_networks): d for d in domains}
        for future in as_completed(future_to_domain):
            res = future.result()
            results.append(res)
            ips_str = ', '.join(res['ips']) if res['ips'] else 'N/A'
            if res['error']:
                status = '❌ 解析失败'
            elif res['is_all_cf']:
                status = '✅ Cloudflare'
            else:
                status = '⚠️  非全CF' if res['cf_ips'] else '❌ 非Cloudflare'
            print(f"  {res['domain']:40s}  {ips_str:30s}  {status}")

    total = len(results)
    cf_only = sum(1 for r in results if r['is_all_cf'])
    non_cf = sum(1 for r in results if r['ips'] and not r['is_all_cf'])
    failed = sum(1 for r in results if not r['ips'])
    print(f"\n📊 总结: 总数={total}  全CF={cf_only}  非CF={non_cf}  解析失败={failed}")

    # 2. 对 CF 域名添加多子域名、多目标 CNAME
    cf_domains = [r['domain'] for r in results if r['is_all_cf']]
    if not cf_domains:
        print("\n🎉 没有发现完全在 Cloudflare 上的域名，无需操作。")
        return

    print(f"\n🔧 共 {len(cf_domains)} 个域名完全在 CF 上:")
    for d in cf_domains:
        print(f"  - {d}")

    if not TENCENT_SECRET_ID or not TENCENT_SECRET_KEY:
        print("\n⚠️  缺少腾讯云 API 密钥，无法执行 DNS 修改。")
        return
    if not CNAME_TARGETS:
        print("\n⚠️  未指定目标 CNAME 地址，请填写 CNAME_TARGETS 列表。")
        return

    print(f"\n📋 子域名列表: {SUB_DOMAINS}")
    print(f"📋 目标 CNAME 列表: {CNAME_TARGETS}")

    if not DO_UPDATE:
        print("\n⚠️  DO_UPDATE = False，仅展示模拟动作，未实际修改。")
        for domain in cf_domains:
            for sub in SUB_DOMAINS:
                for target in CNAME_TARGETS:
                    print(f"    [模拟] 创建 {sub}.{domain} CNAME -> {target}")
        return

    # 真实执行
    print("\n🔨 开始为每个域名、子域名添加 CNAME 记录...")
    for domain in cf_domains:
        print(f"  🌍 处理域名: {domain}")
        for sub in SUB_DOMAINS:
            ensure_cname_records(domain, sub, CNAME_TARGETS, TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    print("✅ 全部完成。")


if __name__ == '__main__':
    main()