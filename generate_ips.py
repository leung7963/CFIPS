#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 采集器（整合版 - 步骤 1/2）
================================================
重写自 Senflare-IP 项目核心逻辑，无外部仓库依赖。

功能：
  1. 从多 API 源并发采集 Cloudflare IP
  2. TCP 连接快速筛选
  3. 并发延迟测试 + 带宽测试
  4. 综合评分排序
  5. 输出 generated_ips.txt（供 push_to_dns.py 使用）

输出文件：
  - generated_ips.txt  : 优选 IP 列表（每行一个 IP）
  - IPlist.txt         : 基础可用 IP 列表
  - IPlist-Pro.txt     : 高级优选 IP 列表
  - Ranking.txt        : 详细排名信息
"""

import os
import re
import sys
import time
import json
import socket
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from urllib3.exceptions import InsecureRequestWarning

# ===== 初始化 =====
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ===== 配置 =====
CONFIG = {
    # IP 采集源（多源并发）
    "ip_sources": [
        'https://api.uouin.com/cloudflare.html',
        'https://api.urlce.com/cloudflare.html',
        'https://addressesapi.090227.xyz/CloudFlareYes',
        'https://cf.090227.xyz/CloudFlareYes',
        'https://vps789.com/openApi/cfIpTop20',
        'https://vps789.com/openApi/cfIpApi',
        'https://www.wetest.vip/page/cloudflare/total_v4.html',
        'https://cf.090227.xyz/cmcc',
        'https://cf.090227.xyz/ct',
    ],
    "test_ports": [443],
    "timeout": 15,
    "api_timeout": 5,
    "query_interval": 0.2,
    "max_workers": 15,
    "batch_size": 10,
    "cache_ttl_hours": 168,
    "advanced_mode": True,
    "bandwidth_test_count": 3,
    "bandwidth_test_size_mb": 10,
    "latency_filter_percentage": 30,
}

# IPv4 正则
IPV4_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# HTTP 会话
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': '*/*',
    'Connection': 'keep-alive',
})
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=3)
session.mount('http://', adapter)
session.mount('https://', adapter)

# 地区缓存
region_cache = {}


# ===== IP 采集 =====
def collect_ips():
    """从多源采集 Cloudflare IP"""
    all_ips = []
    for i, url in enumerate(CONFIG["ip_sources"]):
        try:
            if i > 0:
                time.sleep(CONFIG["query_interval"])
            resp = session.get(url, timeout=CONFIG["timeout"])
            if resp.status_code == 200:
                ips = IPV4_RE.findall(resp.text)
                valid = [ip for ip in ips if all(0 <= int(p) <= 255 for p in ip.split('.'))]
                all_ips.extend(valid)
                logger.info(f"✅ {url} → {len(valid)} 个 IP")
            else:
                logger.warning(f"❌ {url} → HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"❌ {url} → {str(e)[:50]}")
    return sorted(list(set(all_ips)), key=lambda x: [int(p) for p in x.split('.')])


# ===== TCP 快速筛选 =====
def quick_filter_ip(ip):
    """TCP 连接测试，返回 (可用, 延迟ms)"""
    try:
        parts = ip.split('.')
        if len(parts) != 4 or not all(0 <= int(p) <= 255 for p in parts):
            return (False, 0)
    except (ValueError, AttributeError):
        return (False, 0)

    min_delay = float('inf')
    for port in CONFIG["test_ports"]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3)
                start = time.time()
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start) * 1000)
                    min_delay = min(min_delay, delay)
                    if delay < 200:
                        return (True, delay)
        except (socket.timeout, socket.error, OSError):
            continue
    if min_delay != float('inf'):
        return (True, min_delay)
    return (False, 0)


# ===== 并发检测 =====
def test_ips_concurrently(ips):
    """并发 TCP Ping 测试"""
    available = []
    batch_size = CONFIG["batch_size"]
    for i in range(0, len(ips), batch_size):
        batch = ips[i:i + batch_size]
        with ThreadPoolExecutor(max_workers=CONFIG["max_workers"]) as ex:
            future_map = {ex.submit(quick_filter_ip, ip): ip for ip in batch}
            for future in as_completed(future_map, timeout=30):
                ip = future_map[future]
                try:
                    ok, delay = future.result()
                    if ok:
                        available.append((ip, delay))
                except:
                    pass
    return available


# ===== 带宽测试 =====
def test_bandwidth(ip):
    """HTTP 下载测试带宽"""
    test_size = CONFIG["bandwidth_test_size_mb"] * 1024 * 1024
    urls = [
        f"https://speed.cloudflare.com/__down?bytes={test_size}",
        f"https://httpbin.org/bytes/{test_size}",
    ]
    best_speed = 0
    for _ in range(CONFIG["bandwidth_test_count"]):
        for url in urls:
            try:
                start = time.time()
                resp = session.get(url, timeout=15, stream=True)
                if resp.status_code == 200:
                    data_size = 0
                    dl_start = time.time()
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            data_size += len(chunk)
                            if time.time() - dl_start > 10 or data_size > 10 * 1024 * 1024:
                                break
                    dl_time = time.time() - dl_start
                    if dl_time > 0 and data_size > 0:
                        speed = (data_size * 8) / (dl_time * 1000000)
                        best_speed = max(best_speed, speed)
                        if speed > 5:
                            return best_speed
            except:
                continue
    return best_speed


# ===== 综合评分 =====
def calculate_score(delay, bandwidth, stability=100):
    """综合评分 (0-100)"""
    if delay <= 50:    delay_score = 40
    elif delay <= 100:  delay_score = 35
    elif delay <= 200:  delay_score = 30
    elif delay <= 300:  delay_score = 25
    else:               delay_score = max(0, 20 - (delay - 300) / 10)

    if bandwidth >= 50:  bw_score = 30
    elif bandwidth >= 20: bw_score = 25
    elif bandwidth >= 10: bw_score = 20
    elif bandwidth >= 5:  bw_score = 15
    else:                 bw_score = max(0, bandwidth * 3)

    stab_score = min(30, stability * 0.3)
    return round(delay_score + bw_score + stab_score, 1)


# ===== 延迟筛选 =====
def latency_filter(ip_delay_list, percentage=30):
    """取延迟最低的前 N%"""
    if not ip_delay_list:
        return []
    sorted_list = sorted(ip_delay_list, key=lambda x: x[1])
    keep = max(1, int(len(sorted_list) * percentage / 100))
    return sorted_list[:keep]


# ===== 主程序 =====
def main():
    start_time = time.time()
    print("=" * 60)
    print("Cloudflare 优选 IP 采集器（步骤 1/2）")
    print("=" * 60)

    # 1. 采集
    logger.info("📥 采集 IP 地址...")
    all_ips = collect_ips()
    if not all_ips:
        logger.error("❌ 未采集到任何 IP")
        sys.exit(1)
    logger.info(f"🔢 去重后 {len(all_ips)} 个唯一 IP")

    # 2. 快速筛选
    logger.info("🔍 快速筛选（TCP 连接测试）...")
    filtered = []
    for ip in all_ips:
        ok, delay = quick_filter_ip(ip)
        if ok:
            filtered.append((ip, delay))
    logger.info(f"✅ 快速筛选保留 {len(filtered)} 个 IP")
    if not filtered:
        logger.error("❌ 筛选后无可用 IP")
        sys.exit(1)

    # 保存基础列表
    with open('IPlist.txt', 'w') as f:
        for ip, _ in filtered:
            f.write(f"{ip}\n")

    # 3. 延迟排名前 30%
    latency_top = latency_filter(filtered, CONFIG["latency_filter_percentage"])
    logger.info(f"🔍 延迟前 {CONFIG['latency_filter_percentage']}：%保留 {len(latency_top)} 个 IP")

    # 4. 带宽测试 + 评分
    logger.info("⚡ 带宽测试...")
    results = []
    for i, (ip, delay) in enumerate(latency_top, 1):
        bw = test_bandwidth(ip)
        score = calculate_score(delay, bw)
        results.append((ip, delay, bw, score))
        logger.info(f"  [{i}/{len(latency_top)}] {ip} 延迟={delay}ms 带宽={bw:.2f}Mbps 评分={score}")

    # 按评分排序
    results.sort(key=lambda x: x[3], reverse=True)

    # 5. 保存结果
    with open('IPlist-Pro.txt', 'w') as f:
        for ip, _, _, _ in results:
            f.write(f"{ip}\n")

    with open('Ranking.txt', 'w') as f:
        for i, (ip, delay, bw, score) in enumerate(results, 1):
            f.write(f"[{i}/{len(results)}] {ip} 延迟={delay}ms 带宽={bw:.2f}Mbps 评分={score}\n")

    # 6. 输出统一文件（供 push_to_dns.py 使用）
    with open('generated_ips.txt', 'w') as f:
        for ip, _, _, _ in results:
            f.write(f"{ip}\n")

    elapsed = round(time.time() - start_time, 2)
    print(f"\n✅ 步骤 1 完成！共 {len(results)} 个优选 IP，耗时 {elapsed}s")
    print(f"📄 输出文件: generated_ips.txt, IPlist.txt, IPlist-Pro.txt, Ranking.txt")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"未捕获异常: {e}")
        traceback.print_exc()
        sys.exit(1)
