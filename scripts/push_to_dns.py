#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CFIPS DNS 推送器（整合版 - 步骤 2/2）
=====================================
重写自 CFIPS 项目，使用原生模块推送 IP 到腾讯云 DNS。

功能：
  - 读取 generated_ips.txt
  - 清理旧的子域名 A 记录
  - 将 IP 分配到固定子域名（Cloudflare ip.1-1-1 等）
  - 发送 TG 通知
"""

import os
import sys
import time
import ipaddress
import requests
import logging
from pathlib import Path

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ===== 配置 =====
INPUT_FILE = "generated_ips.txt"  # 由 generate_ips.py 生成

# CFIPS 原生常量（内联复用，无需外部模块）
SUB_DOMAINS = ["1-1-1", "1-1-2", "1-2-1", "1-2-2", "2-1-1", "2-1-2", "2-2-1", "2-2-2"]
IPS_PER_SUBDOMAIN = 2  # 每个子域名分配的 IP 数
NEEDED_IPV4 = len(SUB_DOMAINS) * IPS_PER_SUBDOMAIN

# 腾讯云 DNS 配置（需用户填入环境变量）
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID", "")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY", "")
DOMAIN = os.environ.get("DOMAIN", "")

# Telegram 通知（可选）
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


# ===== DNS 操作类（内联复用 CFIPS 核心逻辑） =====
class TencentDNSManager:
    """腾讯云 DNS API 管理器 - 复用 CFIPS dnspod-random.py 核心逻辑"""

    def __init__(self, secret_id, secret_key):
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    @staticmethod
    def _sign_v3(service, action, version, payload, secret_id, secret_key, region=""):
        """签名 V3（复用 CFIPS 逻辑）"""
        import time, json, hashlib, hmac as hmac_mod
        ts = int(time.time())
        httppath = "/"
        querystr = ""
        ct = "application/json"
        headers_key = f"content-type:{ct}\nhost:dnspod.tencentcloudapi.com\n"
        signed_headers = "content-type;host"
        payload_str = json.dumps(payload, separators=(',', ':'))
        hashed_payload = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        canonical = "\n".join(["POST", httppath, querystr, headers_key, signed_headers, hashed_payload])
        algo = "TC3-HMAC-SHA256"
        date = time.strftime("%Y-%m-%d", time.gmtime(ts))
        cred_scope = f"{date}/{service}/tc3_request"
        hashed_canonical = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join([algo, str(ts), cred_scope, hashed_canonical])
        secret_date = hmac_mod.new(("TC3" + secret_key).encode("utf-8"), date.encode("utf-8"), hashlib.sha256).digest()
        secret_service = hmac_mod.new(secret_date, service.encode("utf-8"), hashlib.sha256).digest()
        secret_signing = hmac_mod.new(secret_service, "tc3_request".encode("utf-8"), hashlib.sha256).digest()
        signature = hmac_mod.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
        auth = f"{algo} Credential={secret_id}/{cred_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        headers = {
            "Authorization": auth,
            "Content-Type": ct,
            "Host": "dnspod.tencentcloudapi.com",
            "X-TC-Action": action,
            "X-TC-Version": version,
            "X-TC-Timestamp": str(ts),
            "X-TC-Region": region,
        }
        return headers, payload_str

    def _call(self, action, payload):
        """API 调用"""
        headers, body = self._sign_v3("dnspod", action, "2021-03-23", payload, self.secret_id, self.secret_key)
        resp = self.session.post("https://dnspod.tencentcloudapi.com", headers=headers, data=body, timeout=10)
        return resp.json()

    def delete_records(self, domain, sub, record_type="A"):
        """删除子域名记录"""
        try:
            resp = self._call("DescribeRecordList", {"Domain": domain, "Subdomain": sub})
            records = resp.get("Response", {}).get("RecordList", [])
            for r in records:
                if r.get("Name") == sub and r.get("Type") == record_type:
                    self._call("DeleteRecord", {"Domain": domain, "RecordId": r["RecordId"]})
        except Exception as e:
            logger.warning(f"删除记录异常: {e}")

    def add_record(self, domain, sub, record_type="A", line="默认", value="", weight=1):
        """新增记录"""
        payload = {"Domain": domain, "SubDomain": sub, "RecordType": record_type,
                   "RecordLine": line, "Value": value, "TTL": 600, "Weight": weight}
        return self._call("CreateRecord", payload)


class NotificationManager:
    """Telegram 通知"""

    @staticmethod
    def send(text):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}, timeout=10)
        except:
            pass


# ===== IP 分配逻辑 =====
def distribute_ips(ip_pool):
    """按顺序分配 IP 到子域名"""
    result = {sub: [] for sub in SUB_DOMAINS}
    if not ip_pool:
        return result
    idx = 0
    for sub in SUB_DOMAINS:
        block = ip_pool[idx:idx + IPS_PER_SUBDOMAIN]
        result[sub] = block if block else []
        idx += IPS_PER_SUBDOMAIN
    return result


# ===== 主程序 =====
def main():
    print("=" * 60)
    print("CFIPS DNS 推送器（步骤 2/2）")
    print("=" * 60)

    # 检查环境变量
    if not all([TENCENT_SECRET_ID, TENCENT_SECRET_KEY, DOMAIN]):
        print("❌ 缺少环境变量: TENCENT_SECRET_ID, TENCENT_SECRET_KEY, DOMAIN")
        sys.exit(1)

    # 读取 IP 列表
    ip_file = INPUT_FILE
    if not os.path.isfile(ip_file):
        print(f"❌ 找不到 {ip_file}，请先运行 generate_ips.py")
        sys.exit(1)

    ips = []
    with open(ip_file, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if ip:
                try:
                    ipaddress.ip_address(ip)  # 校验格式
                    ips.append(ip)
                except ValueError:
                    pass
    if not ips:
        print("❌ 无效的 IP 列表")
        sys.exit(1)

    print(f"📥 已读取 {len(ips)} 个 IP")

    # 初始化
    dns = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    # 清理旧记录
    print("🧹 清理旧的 A 记录...")
    for sub in SUB_DOMAINS:
        dns.delete_records(DOMAIN, sub, "A")
    print("✅ 旧记录已清理")

    # 分配并推送
    dist = distribute_ips(ips)
    total = 0
    for sub in SUB_DOMAINS:
        records = dist.get(sub, [])
        if not records:
            logger.info(f"  {sub}.{DOMAIN}: 无 IP 分配")
            continue
        for ip in records:
            dns.add_record(DOMAIN, sub, "A", "默认", ip)
            total += 1
        print(f"  ✅ {sub}.{DOMAIN} → {', '.join(records)}")

    # 生成报告
    report = [
        "<b>Cloudflare 优选 IP DNS 推送报告</b>",
        f"域名: {DOMAIN}",
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"推送 IP: {total}",
        ""
    ]
    for sub in SUB_DOMAINS:
        records = dist.get(sub, [])
        report.append(f"{sub}.{DOMAIN} → {', '.join(records) if records else '无'}")
    final_text = "\n".join(report)

    print("\n" + final_text)
    notifier.send(final_text)
    print(f"\n✅ 完成！共推送 {total} 个 IP 到腾讯云 DNS")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"❌ 未捕获异常: {e}")
        traceback.print_exc()
        sys.exit(1)