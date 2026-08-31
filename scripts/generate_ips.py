#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Senflare-IP 优选 IP 生成器（整合流程 - 步骤 1/2）
=================================================
功能：克隆/更新 Senflare-IP → 运行 IPtest.py 采集优选 IP → 输出统一 IP 列表

以 CFIPS 为核心的整合方案：
  Step 1: 本脚本（generate_ips.py）— 生成 IP 列表
  Step 2: push_to_dns.py — 将 IP 推送到腾讯云 DNS

输出文件: generated_ips.txt（供 push_to_dns.py 使用）
"""

import os
import sys
import re
import subprocess
import shutil
from pathlib import Path

# ===== 配置 =====
SENFLARE_REPO_URL = "https://github.com/Senflare/Senflare-IP.git"
SENFLARE_DIR = "data/senflare_repo"      # Senflare-IP 所在目录（相对本脚本根）
OUTPUT_FILE = "generated_ips.txt"        # 生成的统一 IP 列表文件

# 可选：从哪个输出文件读取 IP（优先 Pro，回退标准）
IP_FILES_PRIORITY = ["IPlist-Pro.txt", "IPlist.txt"]
# 每个 IP 用正则校验
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def get_root_dir():
    """返回项目根目录（本脚本所在目录的父目录）"""
    return Path(__file__).resolve().parent.parent


def prepare_senflare_repo(root: Path):
    """准备 Senflare-IP 代码：已存在则 update，否则克隆"""
    repo_path = root / SENFLARE_DIR
    if repo_path.exists():
        print(f"[INFO] 检测到已有 Senflare-IP，执行 git pull 更新...")
        result = subprocess.run(
            ["git", "-C", str(repo_path), "pull"], capture_output=True, text=True
        )
        print(result.stdout.strip() if result.stdout else "")
        if result.returncode != 0:
            print(f"[WARN] git pull 失败，继续使用现有代码: {result.stderr.strip()}")
    else:
        print(f"[INFO] 克隆 Senflare-IP 到 {repo_path} ...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", SENFLARE_REPO_URL, str(repo_path)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"[ERROR] 克隆失败: {result.stderr.strip()}")
            sys.exit(1)
        print("[OK] 克隆完成")
    return repo_path


def run_senflare_ip(repo_path: Path):
    """在 Senflare-IP 目录内运行 IPtest.py"""
    script = repo_path / "IPtest.py"
    if not script.exists():
        print(f"[ERROR] 未找到 IPtest.py: {script}")
        sys.exit(1)

    print(f"[RUN] 执行 {script} (cwd={repo_path}) ...")
    # stream 输出到控制台，便于日志观察
    result = subprocess.run(
        [sys.executable, "IPtest.py"],
        cwd=str(repo_path),
    )
    if result.returncode != 0:
        print(f"[ERROR] IPtest.py 退出码 {result.returncode}")
        sys.exit(result.returncode)
    return repo_path


def collect_ips(repo_path: Path) -> list:
    """从 Senflare-IP 输出文件提取可用 IP（去重、校验）"""
    ips = []
    seen = set()
    for fname in IP_FILES_PRIORITY:
        fpath = repo_path / fname
        if not fpath.exists():
            print(f"[WARN] 不存在 {fname}，跳过")
            continue
        print(f"[READ] 读取 {fname} ...")
        with open(fpath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # 兼容格式：纯 IP、或 "序号|IP"、或 "#注释" 附加
                candidate = line.split("|")[0].split("#")[0].strip()
                if IPV4_RE.match(candidate) and candidate not in seen:
                    seen.add(candidate)
                    ips.append(candidate)
        # 若前序文件已提供足够 IP，则不再读下一文件
        if len(ips) >= 10:
            break
    return ips


def write_output(root: Path, ips: list):
    """写入统一的 generated_ips.txt"""
    out_path = root / OUTPUT_FILE
    with open(out_path, "w", encoding="utf-8") as f:
        for ip in ips:
            f.write(ip + "\n")
    print(f"[OK] 已写入 {len(ips)} 个 IP 到 {out_path}")


def main():
    root = get_root_dir()
    print("=" * 60)
    print("Senflare-IP 优选 IP 生成器（步骤 1）")
    print("=" * 60)

    # 准备代码
    repo_path = prepare_senflare_repo(root)

    # 安装依赖（如需）
    try:
        import requests
        import urllib3
    except ImportError:
        print("[INFO] 安装 requests/urllib3 ...")
        subprocess.run([sys.executable, "-m", "pip", "install", "requests", "urllib3"], check=True)

    # 运行采集
    run_senflare_ip(repo_path)

    # 提取 IP
    ips = collect_ips(repo_path)
    if not ips:
        print("[ERROR] 未提取到任何 IP")
        sys.exit(1)

    write_output(root, ips)
    print(f"[SUCCESS] 步骤 1 完成，共 {len(ips)} 个优选 IP。可运行 push_to_dns.py 推送。")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"未捕获异常: {e}")
        traceback.print_exc()
        sys.exit(1)
