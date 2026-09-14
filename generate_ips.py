#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CFIPS 优选 IP 采集器（CIDR 扫描版 - 步骤 1/2）
================================================
从指定 CIDR 段生成 IP → HTTP 状态码 403 过滤 → 并发测速 → 输出排序结果。

用法：
  python generate_ips.py                    # 默认 104.26.0.0/16 + 162.159.0.0/16 + 172.64.0.0/13
  python generate_ips.py --cidr 104.26.0.0/20   # 自定义单个 CIDR
  python generate_ips.py --cidr 104.26.0.0/16 162.159.0.0/16   # 多个 CIDR
  python generate_ips.py --cidr 104.26.0.0/16 --workers 100 --timeout 5
"""

import os
import re
import sys
import time
import random
import ipaddress
import socket
import logging
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ===== 默认配置 =====
DEFAULT_CIDRS = ["104.26.0.0/16"]
TEST_URL = "https://speed.cloudflare.com"  # Cloudflare 控制页面，正常 IP 返回 403
HTTP_TIMEOUT = 5        # HTTP 超时（秒）
TCP_TIMEOUT = 3         # TCP 超时（秒）
MAX_WORKERS = 200       # 并发线程数
BATCH_SIZE = 500        # 每批大小
BANDWIDTH_TEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes={size}",
    "https://cp.cloudflare.com/__down?bytes={size}",
]
BANDWIDTH_TEST_SIZE = 5 * 1024 * 1024  # 5MB
BANDWIDTH_TIMEOUT = 15
LATENCY_FILTER_PCT = 30  # 延迟前 30% 进入带宽测试

# ===== 会话 =====
session = requests.Session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
})
adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=100, max_retries=2)
session.mount('http://', adapter)
session.mount('https://', adapter)


# ===== IP 生成 =====
def generate_ips_from_cidr(cidr, sample=0):
    """从 CIDR 生成 IP，sample>0 时随机抽样"""
    net = ipaddress.ip_network(cidr, strict=False)
    all_hosts = [str(ip) for ip in net.hosts()]
    if sample > 0 and len(all_hosts) > sample:
        all_hosts = random.sample(all_hosts, sample)
        logger.info(f"  随机抽样 {sample} 个 IP（共 {net.num_addresses} 个）")
    return all_hosts


# ===== 阶段 1：HTTP 状态码 403 过滤 =====
def check_http_403(ip):
    """检查 IP 是否返回 HTTP 403（Cloudflare 代理特征）"""
    for scheme in ("https", "http"):
        try:
            resp = session.request(
                "HEAD",
                f"{scheme}://{ip}/",
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            if resp.status_code == 403:
                return True
            # 有些 IP 返回 5xx 也算可用
            if resp.status_code in (502, 503, 521, 522, 523, 524, 525, 526):
                return True
        except Exception:
            continue
    return False


def filter_403_ips(ips, max_workers=MAX_WORKERS):
    """并发过滤返回 403 的 IP"""
    valid = []
    total = len(ips)
    done = 0

    for i in range(0, total, BATCH_SIZE):
        batch = ips[i:i + BATCH_SIZE]
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(check_http_403, ip): ip for ip in batch}
            for f in as_completed(futures):
                done += 1
                ip = futures[f]
                try:
                    if f.result():
                        valid.append(ip)
                except:
                    pass
                if done % 1000 == 0:
                    logger.info(f"  HTTP 过滤进度: {done}/{total}（已找到 {len(valid)} 个 403 IP）")

    logger.info(f"✅ HTTP 403 过滤: {total} → {len(valid)} 个 IP")
    return valid


# ===== 阶段 2：TCP 连通性 + 延迟测试 =====
def tcp_ping(ip):
    """TCP 连接测试，返回 (可用, 延迟ms)"""
    min_delay = float('inf')
    for port in (443, 80):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TCP_TIMEOUT)
                start = time.time()
                if s.connect_ex((ip, port)) == 0:
                    delay = round((time.time() - start) * 1000)
                    min_delay = min(min_delay, delay)
                    if delay < 200:
                        return True, delay
        except:
            continue
    return (True, min_delay) if min_delay != float('inf') else (False, 0)


def test_tcp_batch(ips, max_workers=MAX_WORKERS):
    """并发 TCP 测试"""
    available = []
    total = len(ips)
    done = 0

    for i in range(0, total, BATCH_SIZE):
        batch = ips[i:i + BATCH_SIZE]
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(tcp_ping, ip): ip for ip in batch}
            for f in as_completed(futures):
                done += 1
                ip = futures[f]
                try:
                    ok, delay = f.result()
                    if ok:
                        available.append((ip, delay))
                except:
                    pass
                if done % 1000 == 0:
                    logger.info(f"  TCP 测试进度: {done}/{total}（已找到 {len(available)} 个可用 IP）")

    logger.info(f"✅ TCP 测试: {total} → {len(available)} 个可用 IP")
    return available


# ===== 阶段 3：延迟筛选 =====
def latency_filter(ip_delay_list, percentage=LATENCY_FILTER_PCT):
    """取延迟最低的前 N%"""
    if not ip_delay_list:
        return []
    sorted_list = sorted(ip_delay_list, key=lambda x: x[1])
    keep = max(1, int(len(sorted_list) * percentage / 100))
    return sorted_list[:keep]


# ===== 阶段 4：带宽测试 =====
def test_bandwidth(ip):
    """HTTP 下载带宽测试"""
    urls = [url.format(size=BANDWIDTH_TEST_SIZE) for url in BANDWIDTH_TEST_URLS]
    best_speed = 0

    for url in urls:
        for _ in range(3):
            try:
                start = time.time()
                resp = session.get(url, timeout=BANDWIDTH_TIMEOUT, stream=True, verify=False)
                if resp.status_code == 200:
                    data_size = 0
                    dl_start = time.time()
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            data_size += len(chunk)
                            if time.time() - dl_start > 8 or data_size > BANDWIDTH_TEST_SIZE:
                                break
                    dl_time = time.time() - dl_start
                    if dl_time > 0 and data_size > 0:
                        speed = (data_size * 8) / (dl_time * 1_000_000)  # Mbps
                        best_speed = max(best_speed, speed)
                        if speed > 5:
                            return best_speed
            except:
                continue
    return best_speed


# ===== 综合评分 =====
def calculate_score(delay, bandwidth):
    """综合评分 (0-100)：延迟 40% + 带宽 30% + 基础 30%"""
    # 延迟分 (0-40)
    if delay <= 50:    delay_score = 40
    elif delay <= 100: delay_score = 35
    elif delay <= 200: delay_score = 30
    elif delay <= 300: delay_score = 25
    else:              delay_score = max(0, 20 - (delay - 300) / 10)

    # 带宽分 (0-30)
    if bandwidth >= 50:  bw_score = 30
    elif bandwidth >= 20: bw_score = 25
    elif bandwidth >= 10: bw_score = 20
    elif bandwidth >= 5:  bw_score = 15
    else:                 bw_score = max(0, bandwidth * 3)

    # 基础分 (30)
    base_score = 30

    return round(delay_score + bw_score + base_score, 1)


# ===== 保存结果 =====
def _save_results(collected, output_dir, target):
    """实时保存当前结果"""
    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, 'IPlist.txt'), 'w') as f:
        for ip, _, _, _ in collected:
            f.write(f"{ip}\n")

    with open(os.path.join(output_dir, 'IPlist-Pro.txt'), 'w') as f:
        for ip, _, _, _ in collected:
            f.write(f"{ip}\n")

    with open(os.path.join(output_dir, 'Ranking.txt'), 'w') as f:
        for i, (ip, delay, bw, score) in enumerate(collected, 1):
            f.write(f"[{i}/{len(collected)}] {ip} 延迟={delay}ms 带宽={bw:.2f}Mbps 评分={score}\n")

    with open(os.path.join(output_dir, 'generated_ips.txt'), 'w') as f:
        for ip, _, _, _ in collected:
            f.write(f"{ip}\n")


# ===== 主程序 =====
def main():
    parser = argparse.ArgumentParser(description="CFIPS CIDR 扫描优选 IP 采集器")
    parser.add_argument("--cidr", nargs="+", default=DEFAULT_CIDRS, help=f"CIDR 段，可指定多个（默认 {' '.join(DEFAULT_CIDRS)}）")
    parser.add_argument("--sample", type=int, default=0, help="从 CIDR 随机抽样 N 个 IP（0=全部）")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"并发线程数（默认 {MAX_WORKERS}）")
    parser.add_argument("--http-timeout", type=float, default=HTTP_TIMEOUT, help=f"HTTP 超时秒数（默认 {HTTP_TIMEOUT}）")
    parser.add_argument("--skip-bandwidth", action="store_true", help="跳过带宽测试（只用延迟排序）")
    parser.add_argument("--output-dir", default=".", help="输出目录")
    parser.add_argument("--target-count", type=int, default=16, help="目标优选 IP 数量（默认 16，会自动循环生成直到达到）")
    args = parser.parse_args()

    start = time.time()
    target = args.target_count
    max_workers = args.workers
    http_timeout = args.http_timeout

    # 支持多个 CIDR：合并所有网段的 IP
    all_hosts = []
    for cidr in args.cidr:
        net = ipaddress.ip_network(cidr, strict=False)
        all_hosts.extend([str(ip) for ip in net.hosts()])
    # 去重（不同 CIDR 可能有重叠 IP）
    all_hosts = list(dict.fromkeys(all_hosts))

    round_num = 0
    collected = []   # (ip, delay, bw, score)
    seen_ips = set()  # 已测试过的 IP，避免重复

    cidr_summary = " + ".join(args.cidr)
    print("=" * 60)
    print(f"CFIPS CIDR 扫描优选 IP 采集器")
    print(f"目标 CIDR: {cidr_summary}（共 {len(all_hosts)} 个 IP）")
    print(f"目标: 随机抽取直到获得 {target} 个有延迟+带宽的 IP")
    print("=" * 60)

    while len(collected) < target:
        round_num += 1
        # 计算本轮抽样数量：目标的 3 倍或剩余可用 IP 的最小值
        remaining = [ip for ip in all_hosts if ip not in seen_ips]
        if not remaining:
            logger.error(f"❌ CIDR 中所有 IP 已测试完毕，仍差 {target - len(collected)} 个")
            break

        batch_size = min(max(target * 3, 50), len(remaining))
        batch_ips = random.sample(remaining, batch_size)
        seen_ips.update(batch_ips)
        logger.info(f"\n🔄 第 {round_num} 轮：随机抽取 {len(batch_ips)} 个 IP（累计收集 {len(collected)}/{target}）")

        # 阶段 1: HTTP 403 过滤
        logger.info(f"  🌐 HTTP 403 过滤...")
        ips_403 = filter_403_ips(batch_ips, max_workers)
        if not ips_403:
            logger.info(f"  ⏭️ 本轮无 403 IP，继续下一轮")
            continue

        # 阶段 2: TCP 测试
        logger.info(f"  🔍 TCP 测试...")
        tcp_ok = test_tcp_batch(ips_403, max_workers)
        if not tcp_ok:
            logger.info(f"  ⏭️ 本轮无 TCP 可用 IP，继续下一轮")
            continue

        # 阶段 3: 延迟筛选
        latency_top = latency_filter(tcp_ok, LATENCY_FILTER_PCT)
        logger.info(f"  🔍 延迟前 {LATENCY_FILTER_PCT}%：{len(latency_top)} 个 IP")

        # 阶段 4: 带宽测试 + 评分
        if args.skip_bandwidth:
            for ip, delay in latency_top:
                collected.append((ip, delay, 0, calculate_score(delay, 0)))
        else:
            logger.info(f"  ⚡ 带宽测试...")
            for i, (ip, delay) in enumerate(latency_top, 1):
                bw = test_bandwidth(ip)
                score = calculate_score(delay, bw)
                collected.append((ip, delay, bw, score))
                if bw > 0:
                    logger.info(f"    ✅ {ip} 延迟={delay}ms 带宽={bw:.2f}Mbps 评分={score}")
                else:
                    logger.info(f"    ⚠️ {ip} 延迟={delay}ms 带宽=0Mbps（跳过）")

        # 去重（同一 IP 可能多轮出现）
        seen_final = set()
        deduped = []
        for item in collected:
            if item[0] not in seen_final:
                seen_final.add(item[0])
                deduped.append(item)
        collected = deduped

        # 实时保存中间结果
        _save_results(collected, args.output_dir, target)

        logger.info(f"  📊 第 {round_num} 轮结束：累计 {len(collected)}/{target} 个优选 IP")

    # 最终按评分排序
    collected.sort(key=lambda x: x[3], reverse=True)
    collected = collected[:target]  # 只保留目标数量

    # 最终保存
    _save_results(collected, args.output_dir, target)

    elapsed = round(time.time() - start, 1)
    print(f"\n{'='*60}")
    print(f"✅ 完成！共 {len(collected)} 个优选 IP，耗时 {elapsed}s")
    print(f"  测试轮次: {round_num} | 累计测试: {len(seen_ips)} 个 IP")
    print(f"📄 输出文件: generated_ips.txt, IPlist.txt, IPlist-Pro.txt, Ranking.txt")
    print(f"{'='*60}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"未捕获异常: {e}")
        traceback.print_exc()
        sys.exit(1)
