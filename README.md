# CFIPS CIDR 扫描 + DNS 推送

> **目标**：从指定 CIDR 段扫描 Cloudflare 优选 IP → 测速排序 → 推送到腾讯云 DNS。

---

## 🚀 使用方法

### 步骤 1：扫描 CIDR 生成优选 IP

```bash
# 默认扫描 104.26.0.0/16（65536 个 IP）
python generate_ips.py

# 自定义 CIDR 和并发数
python generate_ips.py --cidr 104.26.0.0/20 --workers 100

# 跳过带宽测试（只用延迟排序，速度快）
python generate_ips.py --skip-bandwidth

# 指定输出目录
python generate_ips.py --output-dir ./output
```

**扫描流程（4 阶段）：**

| 阶段 | 说明 | 优化 |
|------|------|------|
| 1. HTTP 403 过滤 | 并发请求，只保留返回 403 的 IP（Cloudflare 代理特征） | 200 线程并发 |
| 2. TCP 测试 | TCP 连通性 + 延迟测量 | 200 线程并发 |
| 3. 延迟筛选 | 取延迟最低的前 30% | 减少带宽测试量 |
| 4. 带宽测试 | HTTP 下载测速 + 综合评分（延迟 40% + 带宽 30% + 基础 30%） | 可用 `--skip-bandwidth` 跳过 |

### 步骤 2：推送到腾讯云 DNS

```bash
# 设置环境变量
export TENCENT_SECRET_ID="your_tencent_secret_id"
export TENCENT_SECRET_KEY="your_tencent_secret_key"
export DOMAIN="your_domain.com"
export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"      # 可选
export TELEGRAM_CHAT_ID="your_telegram_chat_id"          # 可选

# 推送
python push_to_dns.py
```

---

## 📁 输出文件

| 文件 | 说明 |
|------|------|
| `generated_ips.txt` | 评分排序的优选 IP（供 push_to_dns.py 使用） |
| `IPlist.txt` | TCP 可用的全部 IP |
| `IPlist-Pro.txt` | 评分排序的优选 IP |
| `Ranking.txt` | 详细排名（IP + 延迟 + 带宽 + 评分） |

---

## ⚙️ 参数说明

```bash
python generate_ips.py [OPTIONS]

--cidr           CIDR 段（默认 104.26.0.0/16）
--workers        并发线程数（默认 200）
--http-timeout   HTTP 超时秒数（默认 5）
--skip-bandwidth 跳过带宽测试（只用延迟排序）
--output-dir     输出目录（默认当前目录）
```

---

## 📊 示例输出

```
🌐 阶段 1/4: HTTP 403 过滤... → 45000 个 403 IP
🔍 阶段 2/4: TCP 测试... → 38000 个可用 IP
🔍 阶段 3/4: 延迟前 30%：11400 个 IP
⚡ 阶段 4/4: 带宽测试... → 排序完成
✅ 完成！共 11400 个优选 IP，耗时 320s
```
