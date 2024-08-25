import re
import os
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--disable-dev-shm-usage')
chromedriver = "/usr/bin/chromedriver"
os.environ["webdriver.chrome.driver"] = chromedriver

# 目标 URL 列表
urls = ['https://monitor.gacjie.cn/page/cloudflare/ipv4.html', 
        'https://ip.164746.xyz']

# 正则表达式用于匹配 IP 地址
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# 检查 ip.txt 文件是否存在，如果存在则删除它
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 创建一个文件来存储 IP 地址
with open('ip.txt', 'w') as file:
    # 设置浏览器驱动
    driver = webdriver.Chrome(options=chrome_options,executable_path=chromedriver)
    for url in urls:
        # 打开网页
        driver.get(url)
        # 获取页面源代码
        page_source = driver.page_source
        # 使用正则表达式查找 IP 地址
        ip_matches = re.findall(ip_pattern, page_source)
        for ip in ip_matches:
            file.write(ip + '\n')
    driver.quit()

print('IP 地址已保存到 ip.txt 文件中。')