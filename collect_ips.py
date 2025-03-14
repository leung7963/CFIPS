import re
import os
import selenium
import lxml
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

service = Service(ChromeDriverManager().install())
chrome_options = webdriver.ChromeOptions()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--disable-dev-shm-usage')
chromedriver = "/usr/local/bin/chromedriver"
os.environ["webdriver.chrome.driver"] = chromedriver

# 目标 URL 列表
urls = [
'https://raw.githubusercontent.com/leung7963/CFIPS/main/domain_ips.js'
#'https://raw.githubusercontent.com/leung7963/CFIPS/main/myip.js'
#'https://raw.githubusercontent.com/cmliu/WorkerVless2sub/main/addressesapi.txt'
]

# 正则表达式用于匹配 IP 地址
ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# 检查 ip.txt 文件是否存在，如果存在则删除它
if os.path.exists('ip.js'):
    os.remove('ip.js')

# 创建一个文件来存储 IP 地址
with open('ip.js', 'w') as file:
    # 设置浏览器驱动
    driver = webdriver.Chrome(options=chrome_options)
    all_ips = []
    for url in urls:
        # 打开网页
        driver.get(url)
        # 获取页面源代码
        page_source = driver.page_source
        # 使用正则表达式查找 IP 地址
        ip_matches = re.findall(ip_pattern, page_source)
        all_ips.extend(ip_matches)
    driver.quit()

unique_ips = list(set(all_ips))
with open('ip.js', 'w') as file:
    for ip in unique_ips:
        file.write(ip + '\n')

print('IP 地址已去重并保存到 ip.js 文件中。')