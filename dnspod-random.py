#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cloudflare 优选 IP 生成器 + 腾讯云 DNS 更新
- 从 Cloudflare 官网动态获取 CIDR 列表
- 随机生成 IP 并进行高并发测试（期望状态码 403 等）
- 分运营商线路（移动/联通/电信）和默认线路添加 DNS 记录
- 每条记录设置权重为 1
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

# ========== 环境变量读取（带默认值）==========
# 腾讯云配置（必需）
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY")
DOMAIN = os.environ.get("DOMAIN")
RECORD_NAME = os.environ.get("RECORD_NAME", "@")

# IP 数量配置（IPv4）
ISP_IP_COUNT = int(os.environ.get("ISP_IP_COUNT", "2"))
DEFAULT_IP_COUNT = int(os.environ.get("DEFAULT_IP_COUNT", "2"))

# IPv6 专用配置（可选，默认与 IPv4 一致）
ISP_IP_COUNT_V6 = int(os.environ.get("ISP_IP_COUNT_V6", str(ISP_IP_COUNT)))
DEFAULT_IP_COUNT_V6 = int(os.environ.get("DEFAULT_IP_COUNT_V6", str(DEFAULT_IP_COUNT)))

# IP 生成测试配置
TEST_URL_TEMPLATE = os.environ.get("TEST_URL_TEMPLATE", "http://{ip}/")
EXPECTED_STATUS_CODE = int(os.environ.get("EXPECTED_STATUS_CODE", "403"))
REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "5"))
# 并发测试线程数，修改为 100
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "100"))
# 每一个生成任务的最大尝试倍数（生成 N 个 IP，最多尝试 N * MULTIPLIER 次）
ATTEMPT_MULTIPLIER = int(os.environ.get("ATTEMPT_MULTIPLIER", "100"))
GENERATE_IPV6 = os.environ.get("GENERATE_IPV6", "true").lower() == "true"

# Cloudflare CIDR 官方源
CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CF_IPV6_URL = "https://www.cloudflare.com/ips-v6"

# Telegram 通知配置（可选）
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ========== 常量 ==========
# 腾讯云支持的线路名称
LINES = ['移动', '联通', '电信', '默认']


# ========== 腾讯云 API 签名函数 ==========
def sign_v3(service: str, action: str, version: str, payload: dict,
            secret_id: str, secret_key: str, region: str = "",
            timestamp: int = None) -> Tuple[dict, str]:
    """
    腾讯云 API 3.0 签名
    返回 (headers, body_string)
    """
    if timestamp is None:
        timestamp = int(time.time())

    http_method = "POST"
    canonical_uri = "/"
    canonical_querystring = ""
    ct = "application/json"
    canonical_headers = f"content-type:{ct}\nhost:dnspod.tencentcloudapi.com\n"
    signed_headers = "content-type;host"

    # 请求体 JSON 字符串
    payload_str = json.dumps(payload, separators=(',', ':'))
    hashed_payload = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    canonical_request = "\n".join([
        http_method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        hashed_payload
    ])

    algorithm = "TC3-HMAC-SHA256"
    date = time.strftime("%Y-%m-%d", time.gmtime(timestamp))
    credential_scope = f"{date}/{service}/tc3_request"
    hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    string_to_sign = "\n".join([
        algorithm,
        str(timestamp),
        credential_scope,
        hashed_canonical_request
    ])

    # 派生签名密钥
    secret_date = hmac.new(
        ("TC3" + secret_key).encode("utf-8"),
        date.encode("utf-8"),
        hashlib.sha256
    ).digest()
    secret_service = hmac.new(secret_date, service.encode("utf-8"), hashlib.sha256).digest()
    secret_signing = hmac.new(secret_service, "tc3_request".encode("utf-8"), hashlib.sha256).digest()
    signature = hmac.new(secret_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization = (f"{algorithm} Credential={secret_id}/{credential_scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")

    headers = {
        "Authorization": authorization,
        "Content-Type": ct,
        "Host": "dnspod.tencentcloudapi.com",
        "X-TC-Action": action,
        "X-TC-Version": version,
        "X-TC-Timestamp": str(timestamp),
        "X-TC-Region": region,
    }
    return headers, payload_str


# ========== IP 管理类（在线获取 CIDR + 多线程测试）==========
class CloudflareIPManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self._ipv4_cidrs = []
        self._ipv6_cidrs = []

    def fetch_cloudflare_ips(self) -> bool:
        """
        从 Cloudflare 官网动态获取 IPv4 和 IPv6 CIDR 列表
        """
        def get_cidrs(url: str, version: int) -> List[str]:
            print(f"正在从 {url} 获取 IPv{version} CIDR...")
            try:
                response = self.session.get(url, timeout=15)
                response.raise_for_status()
                text = response.text.strip()
                cidrs = []
                for line in text.splitlines():
                    line = line.strip()
                    if not line: continue
                    try:
                        # 校验 CIDR
                        network = ipaddress.ip_network(line, strict=False)
                        if network.version == version:
                            cidrs.append(line)
                    except ValueError:
                        print(f"警告: 无效的 CIDR: {line}")
                if not cidrs:
                    print(f"错误: 从 {url} 未获取到有效的 IPv{version} CIDR")
                else:
                    print(f"成功获取 {len(cidrs)} 个 IPv{version} CIDR")
                return cidrs
            except Exception as e:
                print(f"获取 IPv{version} CIDR 失败: {e}")
                return []

        self._ipv4_cidrs = get_cidrs(CF_IPV4_URL, 4)
        if GENERATE_IPV6:
            self._ipv6_cidrs = get_cidrs(CF_IPV6_URL, 6)

        # 校验结果
        if not self._ipv4_cidrs:
            print("致命错误: 无法获取 IPv4 CIDR 列表。")
            return False
        if GENERATE_IPV6 and not self._ipv6_cidrs:
            print("警告: 开启了 IPv6 生成但未获取到 IPv6 CIDR。")
            # 视情况决定是否终止，这里选择允许仅 IPv4 运行

        return True

    def get_cidrs_by_version(self, is_ipv6: bool) -> List[str]:
        return self._ipv6_cidrs if is_ipv6 else self._ipv4_cidrs

    def generate_random_ip_from_cidr(self, cidr: str, is_ipv6: bool = False) -> Optional[str]:
        """从 CIDR 范围内生成随机 IP 地址"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # 再次确认版本
            if is_ipv6 and network.version != 6: return None
            if not is_ipv6 and network.version != 4: return None

            net_int = int(network.network_address)
            bcast_int = int(network.broadcast_address)

            # 避免生成网络地址和广播地址（对 IPv4 /31,/32 和 IPv6 /127,/128 特殊处理）
            if network.prefixlen <= (126 if is_ipv6 else 30):
                start = net_int + 1
                end = bcast_int - 1
            else:
                # 非常小的子网，直接在范围内生成
                start = net_int
                end = bcast_int

            if start > end:
                return None
            rand_int = random.randint(start, end)
            return str(ipaddress.ip_address(rand_int))
        except Exception:
            return None

    def test_ip_worker(self, ip_address: str) -> Tuple[str, bool, int]:
        """
        单条 IP 测试函数，供线程池调用
        返回: (ip, structure_ok, status_code)
        """
        # 专门为测试创建 Session，避免多线程共享 Session 带来的潜在 TTL/连接池问题
        # 但在极高并发下，频繁创建 Session 可能导致本地端口耗尽，
        # 这里使用全局 session 但配合 requests 的连接池管理。
        # 实际上，requests.Session 是线程安全的，可以直接用。
        
        try:
            # 判断是否为 IPv6 以便正确组装 URL
            is_ipv6 = ':' in ip_address
            if is_ipv6:
                test_url = TEST_URL_TEMPLATE.format(ip=f"[{ip_address}]")
            else:
                test_url = TEST_URL_TEMPLATE.format(ip=ip_address)

            # 使用全局 session 发起请求
            response = self.session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=False)
            status_code = response.status_code
            return ip_address, (status_code == EXPECTED_STATUS_CODE), status_code
        except requests.exceptions.RequestException:
            # 涵盖 Timeout, ConnectionError 等
            return ip_address, False, 0
        except Exception:
            return ip_address, False, -1

    def generate_and_test_ips_concurrent(self, num_ips: int, is_ipv6: bool = False) -> List[str]:
        """并发生成并测试指定数量的合格 IP"""
        if num_ips <= 0:
            return []

        cidr_type = "IPv6" if is_ipv6 else "IPv4"
        print(f"\n开始并发生成 {num_ips} 个 {cidr_type} 合格 IP (最大线程: {MAX_WORKERS})...")

        cidrs = self.get_cidrs_by_version(is_ipv6)
        if not cidrs:
            print(f"错误：无有效的 {cidr_type} CIDR 范围，跳过生成")
            return []

        qualified_ips = []
        attempted_ips = set()
        
        # 目标是寻找 num_ips 个，但为了并发，我们需要一次性投递更多任务
        # 预估合格率，投递任务
        max_total_attempts = num_ips * ATTEMPT_MULTIPLIER
        
        print(f"计划寻找 {num_ips} 个 IP，最大尝试 {max_total_attempts} 次...")

        # 使用线程池
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_ip = {}
            
            # 初始投递批量任务
            batch_size = max(MAX_WORKERS * 2, num_ips * 2)
            
            # 内部函数：生成并投递一个新 IP 测试任务
            def submit_new_ip():
                nonlocal max_total_attempts
                if max_total_attempts <= 0:
                    return False
                
                # 尝试生成一个未测试过的 IP
                ip = None
                for _ in range(10): # 内部重试生成
                    cidr = random.choice(cidrs)
                    generated_ip = self.generate_random_ip_from_cidr(cidr, is_ipv6)
                    if generated_ip and generated_ip not in attempted_ips:
                        ip = generated_ip
                        break
                
                if ip:
                    attempted_ips.add(ip)
                    max_total_attempts -= 1
                    future = executor.submit(self.test_ip_worker, ip)
                    future_to_ip[future] = ip
                    return True
                return False

            # 初始填充任务队列
            for _ in range(min(batch_size, max_total_attempts)):
                if not submit_new_ip(): break

            # 处理结果并动态补充任务
            while future_to_ip and len(qualified_ips) < num_ips:
                # 获取已完成的任务
                for future in as_completed(future_to_ip):
                    ip = future_to_ip.pop(future)
                    
                    try:
                        tested_ip, is_ok, code = future.result()
                        if is_ok:
                            # 再次检查，防止多线程下刚好同时合格
                            if tested_ip not in qualified_ips:
                                qualified_ips.append(tested_ip)
                                print(f"✓ 已找到 {len(qualified_ips)}/{num_ips}: {tested_ip}")
                                
                                # 如果找够了，停止补充任务
                                if len(qualified_ips) >= num_ips:
                                    break
                        else:
                            # 可选：打印不合格详情
                            # print(f"✗ 不合格 {tested_ip} ({code})")
                            pass
                            
                    except Exception as e:
                        print(f"处理测试结果时异常 ({ip}): {e}")

                    # 只要还没找够，且还有尝试机会，就补充一个新任务
                    if len(qualified_ips) < num_ips:
                        if not submit_new_ip():
                            # 无法生成新 IP 或达到最大尝试，且队列已空，则退出
                            if not future_to_ip:
                                break
                    else:
                        break # 找够了，退出 for 循环

        if len(qualified_ips) < num_ips:
            print(f"警告：仅找到 {len(qualified_ips)} 个 {cidr_type} 合格 IP，目标 {num_ips} (尝试次数耗尽)")
        else:
            print(f"成功生成 {len(qualified_ips)} 个 {cidr_type} IP")
            
        return qualified_ips


# ========== 腾讯云 DNS 操作类（直接调用 API）==========
class TencentDNSManager:
    def __init__(self, secret_id: str, secret_key: str):
        self.secret_id = secret_id
        self.secret_key = secret_key
        self.session = requests.Session()
        self.base_url = "https://dnspod.tencentcloudapi.com"
        self.service = "dnspod"
        self.version = "2021-03-23"  # DNSPod API 版本

    def _call_api(self, action: str, payload: dict) -> dict:
        """调用腾讯云 API 并返回响应 JSON"""
        headers, body = sign_v3(
            service=self.service,
            action=action,
            version=self.version,
            payload=payload,
            secret_id=self.secret_id,
            secret_key=self.secret_key
        )
        resp = self.session.post(self.base_url, headers=headers, data=body, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def delete_records_by_type(self, domain: str, sub: str, record_type: str) -> int:
        """删除指定类型的所有记录，返回删除数量"""
        deleted = 0
        try:
            # 获取记录列表
            list_payload = {
                "Domain": domain,
                "Subdomain": sub
            }
            list_resp = self._call_api("DescribeRecordList", list_payload)
            records = list_resp.get("Response", {}).get("RecordList", [])
            if not records:
                print(f"未找到 {sub} 的 {record_type} 记录")
                return 0

            for record in records:
                # 腾讯云 Name 为主机记录，Value 为记录值
                if record.get("Name") == sub and record.get("Type") == record_type:
                    record_id = record.get("RecordId")
                    del_payload = {
                        "Domain": domain,
                        "RecordId": record_id
                    }
                    self._call_api("DeleteRecord", del_payload)
                    print(f"删除记录: {sub} ({record.get('Line')}) [{record_type}] -> {record.get('Value')}")
                    deleted += 1

            print(f"共删除 {deleted} 条 {record_type} 记录")
            return deleted
        except Exception as e:
            print(f"删除记录失败: {e}")
            return 0

    def add_record(self, domain: str, sub: str, record_type: str, line: str, value: str, weight: int = 1) -> bool:
        """添加单条解析记录，支持设置权重"""
        payload = {
            "Domain": domain,
            "SubDomain": sub,
            "RecordType": record_type,
            "RecordLine": line,
            "Value": value,
            "TTL": 600, # TTL 调小一点
            "Weight": weight
        }
        try:
            resp = self._call_api("CreateRecord", payload)
            if "Response" in resp and "Error" not in resp["Response"]:
                print(f"新增记录成功: {sub} ({line}) [{record_type}] 权重={weight} -> {value}")
                return True
            else:
                error = resp.get("Response", {}).get("Error", {}).get("Message", "未知错误")
                print(f"新增记录失败: {sub} -> {value}, 错误: {error}")
                return False
        except Exception as e:
            print(f"添加记录异常: {e}")
            return False


# ========== 通知与保存类 ==========
class NotificationManager:
    @staticmethod
    def send_telegram(text: str):
        if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
            return
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
            requests.post(url, data=payload, timeout=10)
        except Exception as e:
            print(f"发送 Telegram 消息失败: {e}")

    @staticmethod
    def save_to_file(ip_list: List[str], filename: str):
        if not ip_list: return
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for ip in ip_list:
                    f.write(ip + '\n')
            print(f"IP 已保存到本地文件: {filename}")
        except Exception as e:
            print(f"保存文件失败 {filename}: {e}")


# ========== IP 分配函数 ==========
def distribute_ips(ip_pool: List[str], isp_count: int, default_count: int) -> Dict[str, List[str]]:
    """
    将 IP 池分配到各线路
    返回: {'移动':[...], '联通':[...], '电信':[...], '默认':[...]}
    """
    result = {line: [] for line in LINES}
    if not ip_pool:
        return result

    total_needed = isp_count * 3 + default_count  # 移动、联通、电信 + 默认
    
    # 若池子不足，循环复用池子中的 IP
    pool_size = len(ip_pool)
    extended = [ip_pool[i % pool_size] for i in range(total_needed)]
    
    idx = 0
    # 分配移动、联通、电信
    for line in ['移动', '联通', '电信']:
        result[line] = extended[idx:idx + isp_count]
        idx += isp_count
    # 分配默认
    result['默认'] = extended[idx:idx + default_count]
    return result


# ========== 主函数 ==========
def main():
    # 忽略 SSL 警告（因为直接用 IP 访问 HTTP 可能会有证书问题，虽然我们只看状态码）
    requests.packages.urllib3.disable_warnings()

    print("=" * 60)
    print("Cloudflare 优选 IP 生成器 + 腾讯云 DNS 更新 (在线 CIDR + 100并发)")
    print("=" * 60)

    # 检查必要环境变量
    missing = []
    if not TENCENT_SECRET_ID: missing.append("TENCENT_SECRET_ID")
    if not TENCENT_SECRET_KEY: missing.append("TENCENT_SECRET_KEY")
    if not DOMAIN: missing.append("DOMAIN")
    if missing:
        print(f"错误：缺少必要环境变量: {', '.join(missing)}")
        print("请设置 TENCENT_SECRET_ID, TENCENT_SECRET_KEY, DOMAIN")
        sys.exit(1)

    # 初始化管理器
    ip_manager = CloudflareIPManager()
    dns_manager = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    # 1. 在线获取 Cloudflare CIDR
    if not ip_manager.fetch_cloudflare_ips():
        print("致命错误：无法获取 Cloudflare IP 范围，程序退出。")
        sys.exit(1)

    # 计算所需 IP 数量
    needed_ipv4 = ISP_IP_COUNT * 3 + DEFAULT_IP_COUNT  # 移动、联通、电信 + 默认
    needed_ipv6 = ISP_IP_COUNT_V6 * 3 + DEFAULT_IP_COUNT_V6 if GENERATE_IPV6 else 0

    print(f"\n目标配置:")
    print(f"  域名: {DOMAIN}")
    print(f"  主机记录: {RECORD_NAME}")
    print(f"  IPv4: 移动/联通/电信 各 {ISP_IP_COUNT} 个, 默认 {DEFAULT_IP_COUNT} 个 -> 共需优选 {needed_ipv4} 个")
    if GENERATE_IPV6:
        print(f"  IPv6: 移动/联通/电信 各 {ISP_IP_COUNT_V6} 个, 默认 {DEFAULT_IP_COUNT_V6} 个 -> 共需优选 {needed_ipv6} 个")
    print(f"  测试 URL 模板: {TEST_URL_TEMPLATE}")
    print(f"  期望状态码: {EXPECTED_STATUS_CODE}")

    # 2. 并发生成 IPv4 合格 IP 池
    ipv4_pool = ip_manager.generate_and_test_ips_concurrent(needed_ipv4, is_ipv6=False)

    # 3. 并发生成 IPv6 合格 IP 池
    ipv6_pool = []
    if GENERATE_IPV6 and needed_ipv6 > 0:
        ipv6_pool = ip_manager.generate_and_test_ips_concurrent(needed_ipv6, is_ipv6=True)

    # 保存结果到文件（可选）
    notifier.save_to_file(ipv4_pool, "cfip_v4.txt")
    notifier.save_to_file(ipv6_pool, "cfip_v6.txt")

    # 准备通知内容
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    summary = [
        f"<b>Cloudflare 优选 IP 更新报告</b>",
        f"域名: {DOMAIN}",
        f"记录: {RECORD_NAME}",
        f"时间: {current_time}",
        f"",
        f"IPv4 池: {len(ipv4_pool)}/{needed_ipv4}",
    ]
    if GENERATE_IPV6:
        summary.append(f"IPv6 池: {len(ipv6_pool)}/{needed_ipv6}")

    # 4. 更新 DNS 记录
    print("\n开始更新腾讯云 DNS...")
    total_added = 0
    total_deleted = 0

    # 处理 IPv4 (A 记录)
    if ipv4_pool:
        print("\n--- 处理 IPv4 A 记录 ---")
        # 先删除旧记录
        deleted = dns_manager.delete_records_by_type(DOMAIN, RECORD_NAME, 'A')
        total_deleted += deleted

        # 分配并添加新记录
        distribution = distribute_ips(ipv4_pool, ISP_IP_COUNT, DEFAULT_IP_COUNT)
        for line, ips in distribution.items():
            for ip in ips:
                if dns_manager.add_record(DOMAIN, RECORD_NAME, 'A', line, ip):
                    total_added += 1
    else:
        print("警告: IPv4 池为空，跳过 A 记录更新")

    # 处理 IPv6 (AAAA 记录)
    if ipv6_pool:
        print("\n--- 处理 IPv6 AAAA 记录 ---")
        # 先删除旧记录
        deleted = dns_manager.delete_records_by_type(DOMAIN, RECORD_NAME, 'AAAA')
        total_deleted += deleted

        # 分配并添加新记录
        distribution = distribute_ips(ipv6_pool, ISP_IP_COUNT_V6, DEFAULT_IP_COUNT_V6)
        for line, ips in distribution.items():
            for ip in ips:
                if dns_manager.add_record(DOMAIN, RECORD_NAME, 'AAAA', line, ip):
                    total_added += 1
    elif GENERATE_IPV6:
        print("警告: 开启了 IPv6 但 IP 池为空，跳过 AAAA 记录更新")

    # 最终统计
    status_str = '成功' if total_added > 0 or (needed_ipv4==0 and needed_ipv6==0) else '失败（无记录添加）'
    summary.append(f"")
    summary.append(f"DNS 删除: {total_deleted} 条")
    summary.append(f"DNS 新增: {total_added} 条")
    summary.append(f"状态: {status_str}")

    final_report = "\n".join(summary)
    print("\n" + "=" * 60)
    # 打印时不带 HTML 标签
    print(final_report.replace("<b>","").replace("</b>",""))
    print("=" * 60)

    # 发送 Telegram 通知
    notifier.send_telegram(final_report)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"程序异常终止: {e}")
        traceback.print_exc()
        sys.exit(1)