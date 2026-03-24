# WatchVuln

高价值漏洞采集与推送服务，从多个漏洞信息源抓取数据并推送通知。

本项目基于 [zema1/watchvuln](https://github.com/zema1/watchvuln) 修改，适配 GitHub Actions 定时运行场景。

## 支持的数据源

| 名称 | 地址 | 推送策略 |
|-----|------|---------|
| 阿里云漏洞库 | https://avd.aliyun.com/high-risk/list | 高危或严重 |
| 长亭漏洞库 | https://stack.chaitin.com/vuldb/index | 高危或严重 |
| OSCS开源安全情报预警 | https://www.oscs1024.com/cm | 高危或严重 + 预警标签 |
| 奇安信威胁情报中心 | https://ti.qianxin.com/ | 高危或严重 + 特定标签 |
| 微步在线研究响应中心 | https://x.threatbook.com/v5/vulIntelligence | 高危或严重 |
| Seebug漏洞库 | https://www.seebug.org/ | 高危或严重 |
| 启明星辰漏洞通告 | https://www.venustech.com.cn/new_type/aqtg/ | 高危或严重 |
| CISA KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | 全部 |
| Struts2 Security Bulletins | https://cwiki.apache.org/confluence/display/WW/Security+Bulletins | 高危或严重 |

## 支持的推送方式

钉钉、飞书、企业微信、蓝信、Server酱、PushPlus、Slack、Telegram、Bark、自定义Webhook

## 快速开始

### GitHub Actions

1. Fork 本项目
2. 配置 GitHub Secrets（`DINGDING_ACCESS_TOKEN` 和 `DINGDING_SECRET`）
3. 启用 Actions

### Docker

```bash
docker run --restart always -d \
  -e DINGDING_ACCESS_TOKEN=xxxx \
  -e DINGDING_SECRET=xxxx \
  zemal/watchvuln:latest
```

### 二进制

前往 Release 下载对应平台的二进制。

## 配置

### 环境变量

| 变量名 | 说明 | 默认值 |
|-------|------|-------|
| `DB_CONN` | 数据库连接字符串 | `sqlite3://vuln_v3.sqlite3` |
| `DINGDING_ACCESS_TOKEN` | 钉钉机器人 access_token | |
| `DINGDING_SECRET` | 钉钉机器人加签密钥 | |
| `SOURCES` | 启用的数据源 | `avd,ti,oscs,threatbook,seebug,struts2,kev,venustech` |
| `INTERVAL` | 检查周期 | `30m` |
| `ENABLE_CVE_FILTER` | 启用 CVE 去重 | `true` |
| `DIFF` | 跳过初始化，直接检查更新 | |

### 配置文件

支持 YAML 和 JSON 格式：

```yaml
db_conn: sqlite3://vuln_v3.sqlite3
sources: ["avd", "ti", "oscs", "threatbook", "seebug", "struts2", "kev", "venustech"]
interval: 30m
pusher:
  - type: dingding
    access_token: "xxxx"
    sign_secret: "yyyy"
```

## 推送统计

扫描报告会显示：

- **本次扫描收集**: 从数据源收集到的漏洞总数
- **本次推送成功**: 实际推送成功的数量
- **本次跳过(价值不足)**: 因价值过滤被跳过的数量
- **重复未推送(CVE去重)**: 因 CVE 去重被跳过的数量

## 数据库

默认使用 SQLite，支持 MySQL 和 PostgreSQL：

- `sqlite3://filename`
- `mysql://user:pass@host:port/dbname`
- `postgres://user:pass@host:port/dbname`
