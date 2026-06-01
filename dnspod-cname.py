import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

import requests

# 解析超时（秒）
DNS_TIMEOUT = 5
socket.setdefaulttimeout(DNS_TIMEOUT)

# Cloudflare IPv4 范围获取地址
CF_IPV4_URL = 'https://www.cloudflare.com/ips-v4'
# 需检测的域名列表文件（每行一个域名）
DOMAIN_LIST_URL = 'https://raw.githubusercontent.com/leung7963/CFIPS/main/domain.js'


def get_domains_from_url(url):
    """从 URL 读取域名列表（每行一个域名，忽略空行与 # 开头的注释）"""
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    domains = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        domains.append(line)
    # 去重并保持顺序
    seen = set()
    unique_domains = []
    for d in domains:
        if d not in seen:
            seen.add(d)
            unique_domains.append(d)
    return unique_domains


def get_cloudflare_ipv4_networks():
    """获取 Cloudflare 的 IPv4 地址段并返回网络对象列表"""
    resp = requests.get(CF_IPV4_URL, timeout=15)
    resp.raise_for_status()
    networks = []
    for line in resp.text.strip().splitlines():
        line = line.strip()
        if line:
            networks.append(ipaddress.IPv4Network(line))
    return networks


def resolve_a(domain):
    """解析域名的 A 记录，返回 IPv4 地址集合；解析失败返回 None"""
    try:
        addrinfo = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = {addr[4][0] for addr in addrinfo}
        return ips
    except socket.gaierror:
        return None


def check_domain(domain, cf_networks):
    """检查单个域名的 A 记录是否全部属于 Cloudflare"""
    ips = resolve_a(domain)
    if ips is None:
        return {
            'domain': domain,
            'ips': [],
            'cf_ips': [],
            'non_cf_ips': [],
            'is_all_cf': False,
            'error': 'DNS resolve failed'
        }

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


def main():
    print("🔍 Fetching domain list...")
    try:
        domains = get_domains_from_url(DOMAIN_LIST_URL)
    except Exception as e:
        print(f"❌ Failed to fetch domain list: {e}")
        sys.exit(1)
    print(f"✅ Found {len(domains)} domains.\n")

    print("🌐 Fetching Cloudflare IPv4 ranges...")
    try:
        cf_networks = get_cloudflare_ipv4_networks()
    except Exception as e:
        print(f"❌ Failed to fetch Cloudflare IPs: {e}")
        sys.exit(1)
    print(f"✅ Loaded {len(cf_networks)} Cloudflare IPv4 ranges.\n")

    results = []
    print("🚀 Starting DNS checks (A records only)...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_domain = {
            executor.submit(check_domain, domain, cf_networks): domain
            for domain in domains
        }
        for future in as_completed(future_to_domain):
            result = future.result()
            results.append(result)

            # 输出单条结果
            ips_str = ', '.join(result['ips']) if result['ips'] else 'N/A'
            if result['error']:
                status = '❌ Failed'
            elif result['is_all_cf']:
                status = '✅ Cloudflare'
            else:
                status = '⚠️  Not all CF' if result['cf_ips'] else '❌ Not Cloudflare'
            print(f"  {result['domain']:40s}  {ips_str:30s}  {status}")

    # 汇总统计
    total = len(results)
    cf_only = sum(1 for r in results if r['is_all_cf'])
    non_cf = sum(1 for r in results if r['ips'] and not r['is_all_cf'])
    failed = sum(1 for r in results if not r['ips'])

    print(f"\n📊 Summary: Total={total}  Cloudflare-only={cf_only}  Non-Cloudflare={non_cf}  Failed={failed}")


if __name__ == '__main__':
    main()