#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CFIPS DNS 推送器（整合流程 - 步骤 2/2）
======================================
功能：读取 generate_ips.py 输出的 IP 列表 → 使用 CFIPS 原生模块 → 推送到腾讯云 DNS

以 CFIPS 为核心的整合方案：
  Step 1: generate_ips.py — 生成 IP 列表
  Step 2: 本脚本（push_to_dns.py）— 将 IP 推送到腾讯云 DNS

依赖：
  - data/cfips_repo/dnspod-random.py（含 CloudflareIPManager / TencentDNSManager / distribute_to_subdomains 等）
"""

import os
import sys
import time
import ipaddress
from pathlib import Path

# ===== 配置=====
CFIPS_DIR = "data/cfips_repo"          # CFIPS 代码位置（克隆后的路径）
DNSPOD_MODULE = "dnspod_random"        # CFIPS 包含核心逻辑的模块名
INPUT_FILE = "generated_ips.txt"       # 由 generate_ips.py 生成


def get_root_dir():
    return Path(__file__).resolve().parent.parent


def load_cfips_module(root: Path):
    """将 CFIPS 目录加入 sys.path，导入其 dnspod_random 模块"""
    cfips_path = root / CFIPS_DIR
    if not cfips_path.exists():
        print(f"[ERROR] CFIPS 目录不存在: {cfips_path}")
        print("[HINT] 请先克隆 CFIPS 代码: git clone https://github.com/leung7963/CFIPS.git data/cfips_repo")
        sys.exit(1)

    # 加载 CFIPS 的 dnspod_random 模块
    sys.path.insert(0, str(cfips_path))
    try:
        import importlib
        mod = importlib.import_module(DNSPOD_MODULE)
        print(f"[OK] 已加载 CFIPS 模块: {DNSPOD_MODULE}")
        return mod
    except ImportError as e:
        print(f"[ERROR] 导入 CFIPS 模块失败: {e}")
        sys.exit(1)


def read_ips(root: Path) -> list:
    """读取 generated_ips.txt，返回 IP 列表"""
    fpath = root / INPUT_FILE
    if not fpath.exists():
        print(f"[ERROR] 输入文件不存在: {fpath}")
        print("[HINT] 请先运行: python3 scripts/generate_ips.py")
        sys.exit(1)

    ips = []
    with open(fpath, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip and ip_address_is_valid(ip):
                ips.append(ip)
    if not ips:
        print(f"[WARN] {fpath} 中没有有效 IP")
    return ips


def ip_address_is_valid(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def main():
    root = get_root_dir()
    cfips_mod = load_cfips_module(root)

    # 从 CFIPS 模块读取常量（保持与原脚本一致）
    SUB_DOMAINS = getattr(cfips_mod, "SUB_DOMAINS", ["1-1-1", "1-1-2", "1-2-1", "1-2-2", "2-1-1", "2-1-2", "2-2-1", "2-2-2"])
    IPS_PER_SUBDOMAIN = getattr(cfips_mod, "IPS_PER_SUBDOMAIN", 2)
    NEEDED_IPV4 = len(SUB_DOMAINS) * IPS_PER_SUBDOMAIN

    # 读取环境变量（腾讯云 DNS）
    tencent_secret_id = os.environ.get("TENCENT_SECRET_ID")
    tencent_secret_key = os.environ.get("TENCENT_SECRET_KEY")
    domain = os.environ.get("DOMAIN")
    if not all([tencent_secret_id, tencent_secret_key, domain]):
        print("[ERROR] 缺少必要环境变量")
        print("请设置: TENCENT_SECRET_ID, TENCENT_SECRET_KEY, DOMAIN")
        sys.exit(1)

    # 读取 IP 列表
    ips = read_ips(root)
    if not ips:
        sys.exit(1)

    # 初始化腾讯云 DNS 管理器（直接使用 CFIPS 的类）
    dns_manager = cfips_mod.TencentDNSManager(tencent_secret_id, tencent_secret_key)
    distribute_to_subdomains = getattr(cfips_mod, "distribute_to_subdomains", None)
    NotificationManager = getattr(cfips_mod, "NotificationManager", None)

    notifier = NotificationManager()

    print("=" * 60)
    print("CFIPS DNS 推送器（步骤 2）")
    print(f"域名: {domain}")
    print(f"子域名: {SUB_DOMAINS}")
    print(f"每个子域名分配 IP 数: {IPS_PER_SUBDOMAIN}")
    print(f"需要 IP 总数: {NEEDED_IPV4}")
    print(f"已获取 IP 数: {len(ips)}")
    print("=" * 60)

    # 若 IP 不足，提示但继续使用已有 IP
    if len(ips) < NEEDED_IPV4:
        print(f"[WARN] IP 数量不足（{len(ips)}/{NEEDED_IPV4}），将使用全部可用 IP 进行推送（少量子域名可能空缺）")

    # 清理现有子域名 A 记录（保持 CFIPS 的原有逻辑）
    for sub in SUB_DOMAINS:
        dns_manager.delete_records_by_subdomain_and_type(domain, sub, "A")
        print(f"  [清理] 已删除 {sub}.{domain} 的旧 A 记录")

    # 分配 IP 到子域名（复用 CFIPS 方法）
    if distribute_to_subdomains:
        dist = distribute_to_subdomains(ips)  # 按顺序分配
    else:
        # 兜底：手动分配逻辑
        dist = {sub: [] for sub in SUB_DOMAINS}
        for sub in SUB_DOMAINS:
            dist[sub] = ips[:IPS_PER_SUBDOMAIN]
            ips = ips[IPS_PER_SUBDOMAIN:]

    # 推送新记录
    total_pushed = 0
    for sub in SUB_DOMAINS:
        records = dist.get(sub, [])
        if not records:
            print(f"  [跳过] {sub}.{domain} — 无可用 IP")
            continue
        for ip in records:
            dns_manager.add_record(domain, sub, "A", "默认", ip)
            total_pushed += 1
        print(f"  [更新] {sub}.{domain} → {', '.join(records)}")

    # 生成报告 + 发送 TG（复用 CFIPS 的 NotificationManager）
    report = [
        f"<b>Cloudflare 优选 IP DNS 推送报告</b>",
        f"域名: {domain}",
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"推送 IP 总数: {total_pushed}",
        "",
    ]
    for sub in SUB_DOMAINS:
        records = dist.get(sub, [])
        report.append(f"{sub}.{domain} → {', '.join(records) if records else '无'}")
    final_text = "\n".join(report)

    print("\n" + final_text)
    if notifier:
        notifier.send_telegram(final_text)
        print("[TG] 通知已发送")

    print(f"[SUCCESS] 共推送 {total_pushed} 个 IP 到腾讯云 DNS")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"未捕获异常: {e}")
        traceback.print_exc()
        sys.exit(1)
