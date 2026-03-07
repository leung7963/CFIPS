import os
import sys
import time
import random
import ipaddress
import requests
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

# 腾讯云 SDK
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client, models

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
MAX_RETRY_ATTEMPTS = int(os.environ.get("MAX_RETRY_ATTEMPTS", "5"))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "10"))
GENERATE_IPV6 = os.environ.get("GENERATE_IPV6", "true").lower() == "true"

# Telegram 通知配置（可选）
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

# ========== 常量 ==========
LINE_MAP = {
    '移动': '移动',
    '联通': '联通',
    '电信': '电信'
}
LINES = ['移动', '联通', '电信']

# ========== IP 生成与测试类（原 CloudflareIPManager）==========
class CloudflareIPManager:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def get_cloudflare_ips(self) -> Tuple[List[str], List[str]]:
        """从 Cloudflare 获取 IPv4 和 IPv6 地址范围"""
        ipv4_url = "https://www.cloudflare.com/ips-v4/"
        ipv6_url = "https://raw.githubusercontent.com/leung7963/CFIPS/main/cfipv6"

        ipv4_cidrs = []
        ipv6_cidrs = []

        try:
            response = self.session.get(ipv4_url, timeout=10)
            response.raise_for_status()
            ipv4_cidrs = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"获取到 {len(ipv4_cidrs)} 个 IPv4 CIDR 范围")
        except requests.RequestException as e:
            print(f"获取 IPv4 地址范围失败: {e}")

        try:
            response = self.session.get(ipv6_url, timeout=10)
            response.raise_for_status()
            ipv6_cidrs = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"获取到 {len(ipv6_cidrs)} 个 IPv6 CIDR 范围")
        except requests.RequestException as e:
            print(f"获取 IPv6 地址范围失败: {e}")

        return ipv4_cidrs, ipv6_cidrs

    def generate_random_ip_from_cidr(self, cidr: str, is_ipv6: bool = False) -> Optional[str]:
        """从 CIDR 范围内生成随机 IP 地址"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if is_ipv6 and network.version != 6:
                return None
            if not is_ipv6 and network.version != 4:
                return None

            net_int = int(network.network_address)
            bcast_int = int(network.broadcast_address)

            if network.prefixlen <= (126 if is_ipv6 else 30):
                start = net_int + 1
                end = bcast_int - 1
            else:
                start = net_int
                end = bcast_int

            if start > end:
                return None
            rand_int = random.randint(start, end)
            return str(ipaddress.ip_address(rand_int))
        except Exception:
            return None

    def test_ip_status(self, ip_address: str) -> Tuple[bool, int, str]:
        """测试 IP 是否返回期望状态码"""
        try:
            # 判断是否为 IPv6
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                is_ipv6 = (ip_obj.version == 6)
            except ValueError:
                is_ipv6 = ':' in ip_address

            if is_ipv6:
                test_url = TEST_URL_TEMPLATE.format(ip=f"[{ip_address}]")
            else:
                test_url = TEST_URL_TEMPLATE.format(ip=ip_address)

            response = self.session.get(test_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            status_code = response.status_code
            print(f"测试 IP {ip_address}: 状态码 {status_code}")
            return (status_code == EXPECTED_STATUS_CODE), status_code, response.reason
        except requests.exceptions.Timeout:
            print(f"测试 IP {ip_address}: 请求超时")
            return False, 0, "Timeout"
        except requests.exceptions.ConnectionError:
            print(f"测试 IP {ip_address}: 连接错误")
            return False, 0, "Connection Error"
        except Exception as e:
            print(f"测试 IP {ip_address}: 异常 {e}")
            return False, 0, str(e)

    def generate_and_test_ips(self, num_ips: int, is_ipv6: bool = False) -> List[str]:
        """生成并测试指定数量的合格 IP"""
        if num_ips <= 0:
            return []

        cidr_type = "IPv6" if is_ipv6 else "IPv4"
        print(f"\n开始生成 {num_ips} 个 {cidr_type} 合格 IP...")

        ipv4_cidrs, ipv6_cidrs = self.get_cloudflare_ips()
        cidrs = ipv6_cidrs if is_ipv6 else ipv4_cidrs
        if not cidrs:
            print(f"错误：无法获取 {cidr_type} CIDR 范围")
            return []

        qualified = []
        attempted = set()
        total_attempts = 0
        max_attempts = num_ips * 15  # 最多尝试 15 倍数量

        while len(qualified) < num_ips and total_attempts < max_attempts:
            cidr = random.choice(cidrs)
            ip = self.generate_random_ip_from_cidr(cidr, is_ipv6)
            if not ip or ip in attempted:
                total_attempts += 1
                continue

            ok, code, _ = self.test_ip_status(ip)
            attempted.add(ip)
            total_attempts += 1

            if ok:
                qualified.append(ip)
                print(f"✓ 已找到 {len(qualified)}/{num_ips}: {ip}")
            else:
                print(f"✗ 不合格 {ip} (状态码 {code})")

        if len(qualified) < num_ips:
            print(f"警告：仅找到 {len(qualified)} 个 {cidr_type} 合格 IP，目标 {num_ips}")
        else:
            print(f"成功生成 {len(qualified)} 个 {cidr_type} IP")
        return qualified

# ========== 腾讯云 DNS 操作类 ==========
class TencentDNSManager:
    def __init__(self, secret_id: str, secret_key: str):
        self.secret_id = secret_id
        self.secret_key = secret_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            cred = credential.Credential(self.secret_id, self.secret_key)
            httpProfile = HttpProfile()
            httpProfile.endpoint = "dnspod.tencentcloudapi.com"
            clientProfile = ClientProfile()
            clientProfile.httpProfile = httpProfile
            self._client = dnspod_client.DnspodClient(cred, "", clientProfile)
        return self._client

    def delete_records_by_type(self, domain: str, sub: str, record_type: str) -> int:
        """删除指定类型的所有记录，返回删除数量"""
        try:
            req_list = models.DescribeRecordListRequest()
            req_list.Domain = domain
            req_list.Subdomain = sub
            resp = self.client.DescribeRecordList(req_list)

            deleted = 0
            for record in resp.RecordList:
                if record.Name == sub and record.Type == record_type:
                    req_del = models.DeleteRecordRequest()
                    req_del.Domain = domain
                    req_del.RecordId = record.RecordId
                    self.client.DeleteRecord(req_del)
                    print(f"删除记录: {sub} ({record.Line}) [{record.Type}] -> {record.Value}")
                    deleted += 1

            if deleted == 0:
                print(f"未找到 {sub} 的 {record_type} 记录")
            else:
                print(f"共删除 {deleted} 条 {record_type} 记录")
            return deleted
        except Exception as e:
            print(f"删除记录失败: {e}")
            return 0

    def add_record(self, domain: str, sub: str, record_type: str, line: str, value: str) -> bool:
        """添加单条解析记录"""
        try:
            req_add = models.CreateRecordRequest()
            req_add.Domain = domain
            req_add.SubDomain = sub
            req_add.RecordType = record_type
            req_add.RecordLine = line
            req_add.Value = value
            req_add.TTL = 86400  # 24 小时
            self.client.CreateRecord(req_add)
            print(f"新增记录: {sub} ({line}) [{record_type}] -> {value}")
            return True
        except Exception as e:
            print(f"添加记录失败: {sub} ({line}) [{record_type}] -> {value}, 错误: {e}")
            return False

# ========== 通知类 ==========
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
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                for ip in ip_list:
                    f.write(ip + '\n')
            print(f"IP 已保存到 {filename}")
        except Exception as e:
            print(f"保存文件失败 {filename}: {e}")

# ========== IP 分配函数 ==========
def distribute_ips(ip_pool: List[str], isp_count: int, default_count: int) -> Dict[str, List[str]]:
    """
    将 IP 池分配到各线路
    返回: {'移动':[...], '联通':[...], '电信':[...], '默认':[...]}
    """
    result = {line: [] for line in LINES}
    result['默认'] = []
    if not ip_pool:
        return result

    total_needed = isp_count * 3 + default_count
    # 若池子不足，循环复用
    extended = (ip_pool * ((total_needed // len(ip_pool)) + 1))[:total_needed]
    idx = 0
    for line in LINES:
        result[line] = extended[idx:idx + isp_count]
        idx += isp_count
    result['默认'] = extended[idx:idx + default_count]
    return result

# ========== 主函数 ==========
def main():
    print("=" * 60)
    print("Cloudflare 优选 IP 生成器 + 腾讯云 DNS 更新")
    print("=" * 60)

    # 检查必要环境变量
    missing = []
    if not TENCENT_SECRET_ID:
        missing.append("TENCENT_SECRET_ID")
    if not TENCENT_SECRET_KEY:
        missing.append("TENCENT_SECRET_KEY")
    if not DOMAIN:
        missing.append("DOMAIN")
    if missing:
        print(f"错误：缺少必要环境变量: {', '.join(missing)}")
        sys.exit(1)

    # 初始化管理器
    ip_manager = CloudflareIPManager()
    dns_manager = TencentDNSManager(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
    notifier = NotificationManager()

    # 计算所需 IP 数量
    needed_ipv4 = ISP_IP_COUNT * 3 + DEFAULT_IP_COUNT
    needed_ipv6 = ISP_IP_COUNT_V6 * 3 + DEFAULT_IP_COUNT_V6 if GENERATE_IPV6 else 0

    print(f"\n目标配置:")
    print(f"  域名: {DOMAIN}")
    print(f"  主机记录: {RECORD_NAME}")
    print(f"  IPv4: 每运营商 {ISP_IP_COUNT} 个, 默认 {DEFAULT_IP_COUNT} 个 -> 共需 {needed_ipv4} 个")
    if GENERATE_IPV6:
        print(f"  IPv6: 每运营商 {ISP_IP_COUNT_V6} 个, 默认 {DEFAULT_IP_COUNT_V6} 个 -> 共需 {needed_ipv6} 个")

    # 生成 IPv4 合格 IP 池
    ipv4_pool = ip_manager.generate_and_test_ips(needed_ipv4, is_ipv6=False)

    # 生成 IPv6 合格 IP 池
    ipv6_pool = []
    if GENERATE_IPV6 and needed_ipv6 > 0:
        ipv6_pool = ip_manager.generate_and_test_ips(needed_ipv6, is_ipv6=True)

    # 保存到文件（可选）
    if ipv4_pool:
        notifier.save_to_file(ipv4_pool, "cfip.txt")
    if ipv6_pool:
        notifier.save_to_file(ipv6_pool, "cfipv6.txt")

    # 准备通知内容
    summary = [
        f"<b>Cloudflare 优选 IP 更新</b>",
        f"域名: {DOMAIN}",
        f"记录: {RECORD_NAME}",
        f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"IPv4 合格数量: {len(ipv4_pool)} (需求 {needed_ipv4})",
    ]
    if GENERATE_IPV6:
        summary.append(f"IPv6 合格数量: {len(ipv6_pool)} (需求 {needed_ipv6})")

    # 更新 DNS 记录
    print("\n开始更新腾讯云 DNS...")
    total_added = 0
    total_deleted = 0

    # 处理 IPv4 (A 记录)
    if ipv4_pool:
        print("\n--- 处理 IPv4 A 记录 ---")
        deleted = dns_manager.delete_records_by_type(DOMAIN, RECORD_NAME, 'A')
        total_deleted += deleted

        distribution = distribute_ips(ipv4_pool, ISP_IP_COUNT, DEFAULT_IP_COUNT)
        for line, ips in distribution.items():
            for ip in ips:
                if dns_manager.add_record(DOMAIN, RECORD_NAME, 'A', line, ip):
                    total_added += 1
    else:
        print("IPv4 池为空，跳过更新")

    # 处理 IPv6 (AAAA 记录)
    if ipv6_pool:
        print("\n--- 处理 IPv6 AAAA 记录 ---")
        deleted = dns_manager.delete_records_by_type(DOMAIN, RECORD_NAME, 'AAAA')
        total_deleted += deleted

        distribution = distribute_ips(ipv6_pool, ISP_IP_COUNT_V6, DEFAULT_IP_COUNT_V6)
        for line, ips in distribution.items():
            for ip in ips:
                if dns_manager.add_record(DOMAIN, RECORD_NAME, 'AAAA', line, ip):
                    total_added += 1
    elif GENERATE_IPV6:
        print("IPv6 池为空，跳过更新")

    # 最终统计
    summary.append(f"")
    summary.append(f"删除记录: {total_deleted} 条")
    summary.append(f"新增记录: {total_added} 条")
    summary.append(f"状态: {'成功' if total_added > 0 else '失败（无记录添加）'}")

    print("\n" + "=" * 60)
    print("\n".join(summary))
    print("=" * 60)

    # 发送 Telegram 通知
    notifier.send_telegram("\n".join(summary))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"程序异常: {e}")
        traceback.print_exc()
        sys.exit(1)