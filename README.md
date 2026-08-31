# CFIPS 整合流程（Senflare-IP + CFIPS）

> **目标**：利用 **Senflare-IP 核心逻辑**采集优选 IP → 使用 **CFIPS 原生 DNS 逻辑**推送到腾讯云 DNS。
> **特点**：**完全重写**，无外部仓库克隆，代码独立、可维护。

---

## 📁 目录结构

```
CFIPS/
├── .github/workflows/
│   └── cfips-integration.yml     # CI/CD 工作流（自动运行 / 手动触发）
├── scripts/
│   ├── generate_ips.py           # 步骤 1: 重写 Senflare-IP 核心，生成 generated_ips.txt
│   └── push_to_dns.py            # 步骤 2: 重写 CFIPS DNS 推送逻辑
├── generated_ips.txt             # 生成的优选 IP 列表（由 generate_ips.py 产出）
├── IPlist.txt                    # 基础可用 IP 列表
├── IPlist-Pro.txt                # 高级优选 IP 列表
├── Ranking.txt                   # 详细排名信息
└── README.md                     # 本文档
```

---

## 🚀 使用方法

### 本地运行

```bash
# 0. 进入 CFIPS 目录
cd CFIPS

# 1. 安装依赖
pip install requests

# 2. 设置环境变量
export TENCENT_SECRET_ID="your_tencent_secret_id"
export TENCENT_SECRET_KEY="your_tencent_secret_key"
export DOMAIN="your_domain.com"
export TELEGRAM_BOT_TOKEN="your_telegram_bot_token"      # 可选
export TELEGRAM_CHAT_ID="your_telegram_chat_id"          # 可选

# 3. 运行整合流程
python scripts/generate_ips.py    # 第一步: 生成 IP
python scripts/push_to_dns.py     # 第二步: 推送到 DNS
```

---

### GitHub Actions 自动运行

该仓库已包含 `.github/workflows/cfips-integration.yml`：

- **定时触发**：每 3 个小时执行一次（UTC）。
- **手动触发**：GitHub → Actions → `CFIPS 整合流程` → 点击 "Run workflow"。

**首次使用前，请在 GitHub 仓库中配置 Secrets：**

| 变量名 | 说明 | 是否必填 |
|--------|------|-----|
| `TENCENT_SECRET_ID` | 腾讯云 Secret ID | ✅ |
| `TENCENT_SECRET_KEY` | 腾讯云 Secret Key | ✅ |
| `DOMAIN` | 需要更新的域名 | ✅ |
| `TG_BOT_TOKEN` | TG 通知 Bot Token | 可选 |
| `TG_CHAT_ID` | TG 通知接收者 ID | 可选 |

---

## 🔧 脚本说明

### 1. `scripts/generate_ips.py`

**重写自 Senflare-IP 核心逻辑**：

- 多 API 源并发采集 Cloudflare IP（9 个源）
- TCP 连接快速筛选（去除不可用 IP）
- 并发 TCP Ping 测试（测延迟）
- HTTP 下载带宽测试
- 综合评分排序（延迟 40% + 带宽 30% + 稳定性 30%）
- 输出：`generated_ips.txt`（供 push_to_dns.py 使用）、`IPlist.txt`、`IPlist-Pro.txt`、`Ranking.txt`

### 2. `scripts/push_to_dns.py`

**重写自 CFIPS DNS 推送逻辑**：

- 读取 `generated_ips.txt`
- 内联 `TencentDNSManager`（腾讯云 DNS V3 签名 + API 调用）
- 内联 `NotificationManager`（TG 通知）
- 内联 `distribute_ips`（按顺序分配 IP 到固定子域名）
- 清除旧子域名 A 记录 → 写入新记录 → 发送 TG 通知

> ⚠️ **无外部依赖**：所有 CFIPS 核心逻辑已内联，不导入外部模块。

---

## 📝 自定义扩展

### 修改子域名策略

编辑 `scripts/push_to_dns.py` 顶部的常量：

```python
SUB_DOMAINS = ["1-1-1", "1-1-2", "1-2-1", "1-2-2", "2-1-1", "2-1-2", "2-2-1", "2-2-2"]
IPS_PER_SUBDOMAIN = 2
```

### 修改 IP 采集源

编辑 `scripts/generate_ips.py` 中的 `CONFIG["ip_sources"]`。

### 修改评分权重

编辑 `scripts/generate_ips.py` 中的 `calculate_score()` 函数。

---

## 🛡️ 安全说明

- **密钥不存放于代码中**：使用环境变量 / GitHub Secrets。
- **无外部克隆**：完全自包含，供应链安全。
- **可审计的变更范围**：所有逻辑均在本仓库内。

---

## 🔄 更新维护

如需更新 Senflare-IP 或 CFIPS 上游逻辑：

1. 查看对应上游仓库的最新代码
2. 将关键变更同步到 `scripts/generate_ips.py` 或 `scripts/push_to_dns.py`
3. 提交并推送即可

---

## 💡 故障排查

| 问题 | 处理 |
|-----|------|
| `生成 0 个 IP` | 检查网络连通性，API 源可能被限流；可增大 `max_workers` 或 `timeout` |
| `推送失败` | 检查腾讯云 Secret 是否正确，域名是否存在 |
| `TG 通知收不到` | 检查 `TG_BOT_TOKEN` 和 `TG_CHAT_ID` |
| `权限报错` | GitHub Actions 需开启 `contents: write` 权限 |

---

## License

本整合脚本使用 Apache-2.0 协议。参考了 Senflare-IP 和 CFIPS 的开源代码，保留原仓库 LICENSE。

🚀 **Happy Optimizing!**