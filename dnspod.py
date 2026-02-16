import os
import sys
import requests
import re
from bs4 import BeautifulSoup
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client, models

# ========== 从环境变量读取配置（支持默认值，方便本地调试）==========
TENCENT_SECRET_ID = os.environ.get("TENCENT_SECRET_ID", "你的SecretId")
TENCENT_SECRET_KEY = os.environ.get("TENCENT_SECRET_KEY", "你的SecretKey")
DOMAIN = os.environ.get("DOMAIN", "example.com")
RECORD_NAME = os.environ.get("RECORD_NAME", "@")
ISP_IP_COUNT = int(os.environ.get("ISP_IP_COUNT", "2"))
DEFAULT_IP_COUNT = int(os.environ.get("DEFAULT_IP_COUNT", "2"))
# IPv6 专用配置（可选，默认与 IPv4 一致）
ISP_IP_COUNT_V6 = int(os.environ.get("ISP_IP_COUNT_V6", str(ISP_IP_COUNT)))
DEFAULT_IP_COUNT_V6 = int(os.environ.get("DEFAULT_IP_COUNT_V6", str(DEFAULT_IP_COUNT)))
# Telegram 通知配置（可选，不填则不发送）
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
# ==============================================================

LINE_MAP = {
    '移动': '移动',
    '联通': '联通',
    '电信': '电信'
}

def send_telegram_message(text):
    """发送 Telegram 消息（忽略发送失败）"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML"
        }
        requests.post(url, data=payload, timeout=10)
    except Exception as e:
        print(f"发送 Telegram 消息失败: {e}")

def fetch_ips_from_wetest(url, ip_type='v4'):
    """
    通用抓取函数，从指定URL获取IP列表
    ip_type: 'v4' 或 'v6'，用于验证
    返回字典 { '移动': [ip1,ip2,...], '联通': [...], '电信': [...] }
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        print(f"正在抓取 {url} ...")
        resp = requests.get(url, headers=headers, timeout=15)
        resp.encoding = 'utf-8'
        soup = BeautifulSoup(resp.text, 'html.parser')
        table = soup.find('table')
        if not table:
            print(f"警告：{url} 未找到表格，页面结构可能已变化")
            return {}
        rows = table.find_all('tr')[1:]
        result = {'移动': [], '联通': [], '电信': []}
        for row in rows:
            cols = row.find_all('td')
            if len(cols) >= 2:
                isp = cols[0].text.strip()
                ip = cols[1].text.strip()
                # 验证IP格式
                valid = False
                if ip_type == 'v4':
                    # IPv4 简单正则
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        valid = True
                else:
                    # IPv6 宽松验证：包含冒号且不是IPv4格式
                    if ':' in ip and not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        valid = True
                if valid and isp in result:
                    if ip not in result[isp]:
                        result[isp].append(ip)
        # 调试输出：打印每个运营商的前几个IP
        for isp, ips in result.items():
            if ips:
                print(f"  抓取到 {isp} IPv{ip_type}: {ips[:3]}... (共{len(ips)}个)")
        return result
    except Exception as e:
        print(f"抓取失败 {url}: {e}")
        return {}

def delete_all_records(domain, sub, record_type=None):
    """
    删除指定主机记录下的记录
    record_type: 如果指定，只删除该类型的记录（如 'A' 或 'AAAA'）；为 None 则删除所有类型
    """
    try:
        cred = credential.Credential(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "dnspod.tencentcloudapi.com"
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = dnspod_client.DnspodClient(cred, "", clientProfile)

        req_list = models.DescribeRecordListRequest()
        req_list.Domain = domain
        req_list.Subdomain = sub
        resp_list = client.DescribeRecordList(req_list)

        deleted_count = 0
        for record in resp_list.RecordList:
            # 如果指定了类型，则只匹配该类型
            if record.Name == sub and (record_type is None or record.Type == record_type):
                req_del = models.DeleteRecordRequest()
                req_del.Domain = domain
                req_del.RecordId = record.RecordId
                client.DeleteRecord(req_del)
                deleted_count += 1
                print(f"删除旧记录: {sub} ({record.Line}) [{record.Type}] -> {record.Value}")

        if deleted_count == 0:
            type_info = f"类型 {record_type} " if record_type else ""
            print(f"未找到 {sub} 的 {type_info}现有记录")
        else:
            print(f"共删除 {deleted_count} 条记录")
        return deleted_count  # 返回删除数量以便统计
    except Exception as e:
        print(f"删除记录失败: {e}")
        return 0

def add_record(domain, sub, record_type, line, value):
    """添加单条解析记录，返回是否成功"""
    try:
        cred = credential.Credential(TENCENT_SECRET_ID, TENCENT_SECRET_KEY)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "dnspod.tencentcloudapi.com"
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = dnspod_client.DnspodClient(cred, "", clientProfile)

        req_add = models.CreateRecordRequest()
        req_add.Domain = domain
        req_add.SubDomain = sub
        req_add.RecordType = record_type
        req_add.RecordLine = line
        req_add.Value = value
        client.CreateRecord(req_add)
        print(f"新增记录: {sub} ({line}) [{record_type}] -> {value}")
        return True
    except Exception as e:
        print(f"添加记录失败 {sub} ({line}) [{record_type}]: {e}")
        return False

def process_ip_type(ip_dict, record_type, isp_count, default_count, type_name):
    """
    处理一种IP类型（IPv4或IPv6）的添加逻辑，返回成功添加的记录数
    ip_dict: 抓取结果字典
    record_type: 'A' 或 'AAAA'
    isp_count: 每个运营商添加的IP数
    default_count: 默认线路添加的IP数
    type_name: 用于打印的字符串（如 'IPv4'）
    """
    if not ip_dict:
        print(f"{type_name} 无数据，跳过")
        return 0

    for isp, ips in ip_dict.items():
        print(f"{type_name} {isp}: 共 {len(ips)} 个IP，将取前 {min(isp_count, len(ips))} 个用于分线路")

    all_ips = []
    for ips in ip_dict.values():
        all_ips.extend(ips)
    all_ips_unique = []
    for ip in all_ips:
        if ip not in all_ips_unique:
            all_ips_unique.append(ip)
    print(f"{type_name} 全局去重IP共 {len(all_ips_unique)} 个，将取前 {min(default_count, len(all_ips_unique))} 个用于默认线路")

    added_count = 0
    # 添加分线路记录
    for isp, ips in ip_dict.items():
        if isp not in LINE_MAP:
            print(f"跳过未知运营商: {isp}")
            continue
        line = LINE_MAP[isp]
        for ip in ips[:isp_count]:
            if add_record(DOMAIN, RECORD_NAME, record_type, line, ip):
                added_count += 1

    # 添加默认线路记录
    if default_count > 0:
        for ip in all_ips_unique[:default_count]:
            if add_record(DOMAIN, RECORD_NAME, record_type, "默认", ip):
                added_count += 1

    return added_count

def main():
    try:
        print("="*50)
        print("开始获取优选IP列表...")
        print("="*50)
        
        # 抓取 IPv4
        print("\n--- 抓取 IPv4 地址 ---")
        ipv4_dict = fetch_ips_from_wetest(
            "https://www.wetest.vip/page/cloudflare/address_v4.html", 
            ip_type='v4'
        )
        # 抓取 IPv6
        print("\n--- 抓取 IPv6 地址 ---")
        ipv6_dict = fetch_ips_from_wetest(
            "https://www.wetest.vip/page/cloudflare/address_v6.html", 
            ip_type='v6'
        )

        # 汇总统计
        print("\n" + "="*50)
        print("抓取结果汇总：")
        v4_stats = {isp: len(ipv4_dict.get(isp, [])) for isp in ['移动', '联通', '电信']}
        v6_stats = {isp: len(ipv6_dict.get(isp, [])) for isp in ['移动', '联通', '电信']}
        print(f"IPv4: 移动 {v4_stats['移动']} 个, 联通 {v4_stats['联通']} 个, 电信 {v4_stats['电信']} 个")
        print(f"IPv6: 移动 {v6_stats['移动']} 个, 联通 {v6_stats['联通']} 个, 电信 {v6_stats['电信']} 个")
        print("="*50)

        if not ipv4_dict and not ipv6_dict:
            msg = "未获取到任何IP，程序退出"
            print(msg)
            send_telegram_message(f"❌ Cloudflare IP 更新失败\n{msg}")
            sys.exit(1)

        print("\n开始同步到腾讯云解析（全量替换模式）...")

        total_added = 0
        total_deleted = 0

        # 处理 IPv4 记录
        print("\n--- 处理 IPv4 记录 (A) ---")
        if ipv4_dict:
            deleted = delete_all_records(DOMAIN, RECORD_NAME, record_type='A')
            total_deleted += deleted
            added = process_ip_type(ipv4_dict, 'A', ISP_IP_COUNT, DEFAULT_IP_COUNT, "IPv4")
            total_added += added
        else:
            print("IPv4 无数据，跳过删除和添加")

        # 处理 IPv6 记录
        print("\n--- 处理 IPv6 记录 (AAAA) ---")
        if ipv6_dict:
            deleted = delete_all_records(DOMAIN, RECORD_NAME, record_type='AAAA')
            total_deleted += deleted
            added = process_ip_type(ipv6_dict, 'AAAA', ISP_IP_COUNT_V6, DEFAULT_IP_COUNT_V6, "IPv6")
            total_added += added
        else:
            print("IPv6 无数据，跳过删除和添加")

        print("\n" + "="*50)
        print("所有同步操作完成")
        print("="*50)

        # 构建成功通知消息
        msg = f"""✅ Cloudflare 优选 IP 更新成功
域名: {DOMAIN}
记录: {RECORD_NAME}

抓取结果:
IPv4: 移动 {v4_stats['移动']} | 联通 {v4_stats['联通']} | 电信 {v4_stats['电信']}
IPv6: 移动 {v6_stats['移动']} | 联通 {v6_stats['联通']} | 电信 {v6_stats['电信']}

操作统计:
删除记录: {total_deleted} 条
新增记录: {total_added} 条

分线路配置:
IPv4 每运营商前 {ISP_IP_COUNT} 个，默认前 {DEFAULT_IP_COUNT} 个
IPv6 每运营商前 {ISP_IP_COUNT_V6} 个，默认前 {DEFAULT_IP_COUNT_V6} 个
"""
        send_telegram_message(msg)

    except Exception as e:
        error_msg = f"❌ Cloudflare IP 更新执行异常: {str(e)}"
        print(error_msg)
        send_telegram_message(error_msg)
        sys.exit(1)

if __name__ == "__main__":
    main()