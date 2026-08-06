# VulnScanner 部署指南 / Deployment Guide

本文介绍 Docker Compose 一键部署、Agent 安装与日常运维。生产环境请先修改所有占位密钥。

## 1. Docker Compose 一键部署 / Quick Start

前置条件：Docker 20.10+（含 Compose v2），可访问外网拉取镜像与 CVE 数据源。

```bash
cd deploy/docker-compose
cp ../../.env.example .env   # 按需修改 JWT_SECRET / API_KEY / SERVER_URL 等
docker compose up -d --build
curl http://localhost:8080/health
```

首次启动会自动拉起 PostgreSQL 16 并运行数据库迁移，随后开始按周期刷新 MSRC/NVD/OSV/Debian/Red Hat 数据源。
仓库根目录执行 `make docker-up` / `make docker-down` / `make docker-build` 效果相同。

### 端口 / Ports

| 端口 | 用途 |
| --- | --- |
| 8080 | REST API（X-API-Key 或用户 Bearer JWT 鉴权；`/health`、`/demo`、`/api/v1/register`、`/api/v1/auth/login`、`/api/v1/auth/ldap/login`、`/dl/*`、`/r/*` 免鉴权） |
| 9090 | Agent gRPC（JWT 鉴权） |
| 5432 | PostgreSQL（仅本机暴露，可用 `POSTGRES_PORT` 修改） |

### 环境变量 / Environment Variables

容器内 server 无需 `server.yaml`，以下变量直接生效（`deploy/docker-compose/.env` 或 shell 环境均可）：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `JWT_SECRET` | `change-me-in-production` | Agent gRPC JWT 签名密钥，**生产必改** |
| `API_KEY` | `sk-change-me` | REST X-API-Key，**生产必改** |
| `SERVER_URL` | `http://localhost:8080` | Agent 可达的 Server 对外地址（注册/安装脚本使用），**生产必改**，如 `https://vuln.example.com` |
| `DATABASE_URL` | 由 compose 自动拼装 | 覆盖时需指向 `postgres` 服务 |
| `VULNSCAN_MODE` | `all` | 运行模式：`all`（默认，API+gRPC+后台循环）/ `api`（仅 API/gRPC）/ `worker`（仅后台循环）；多实例水平扩展时使用 |
| `POSTGRES_PASSWORD` | `vulnscan` | PostgreSQL 密码，**生产必改** |
| `POSTGRES_USER` | `vulnscan` | PostgreSQL 用户 |
| `POSTGRES_PORT` | `5432` | 宿主机映射端口 |
| `HTTP_PORT` / `GRPC_PORT` | `8080` / `9090` | 宿主机映射端口 |
| `NVD_API_KEY` | 空 | 可选，提高 NVD 刷新速率（0.6 秒/请求） |
| `SMTP_PASSWORD` | 空 | 告警邮件密码（对应 `alerting.smtp.password_env`） |
| `LDAP_ENABLED` | `false` | 启用 LDAP 目录登录（对应 `ldap.enabled`） |
| `LDAP_URL` | 空 | LDAP 服务器地址，`ldap://` 或 `ldaps://` |
| `LDAP_TLS_SKIP_VERIFY` | `false` | 仅对 `ldaps://` 生效，跳过证书校验（测试环境） |
| `LDAP_BIND_DN` | 空 | LDAP 服务账号 DN（用户/组搜索） |
| `LDAP_BIND_PASSWORD` | 空 | LDAP 服务账号密码；仅从环境变量读取，不落配置文件 |
| `LDAP_BIND_PASSWORD_ENV` | `LDAP_BIND_PASSWORD` | 指定存放 bind 密码的环境变量名（默认直接用 `LDAP_BIND_PASSWORD`） |
| `LDAP_USER_BASE_DN` | 空 | 用户搜索基点 |
| `LDAP_USER_FILTER` | 空 | 用户过滤，支持 `{username}`，如 `(uid={username})` |
| `LDAP_GROUP_BASE_DN` | 空 | 组搜索基点 |
| `LDAP_GROUP_FILTER` | 空 | 组过滤，支持 `{dn}`/`{username}`，如 `(member={dn})` |
| `LDAP_ROLE_GROUPS` | 空 | JSON 对象，如 `{"admin":["cn=admins,dc=example,dc=org"],"viewer":["viewers"]}` |
| `LDAP_AUTO_PROVISION` | `false` | 首次登录自动创建本地用户 |
| `LDAP_TIMEOUT_SECONDS` | `10` | LDAP 连接/请求超时 |
| `REMOTE_SCAN_ENABLED` | `false` | 启用服务端凭据远程扫描（对应 `remote_scan.enabled`） |
| `REMOTE_SCAN_MASTER_KEY` | 空 | AES-256 主密钥（hex/base64 32 字节），加密远程凭据；**仅环境变量，不落配置** |
| `REMOTE_SCAN_MASTER_KEY_ENV` | `REMOTE_SCAN_MASTER_KEY` | 指定存放主密钥的环境变量名（默认直接用 `REMOTE_SCAN_MASTER_KEY`） |
| `REMOTE_SCAN_TIMEOUT_SECONDS` | `30` | 单条远程命令超时 |
| `REMOTE_SCAN_CONCURRENCY` | `8` | 并发扫描任务数（1-64） |
| `TICKET_ENABLED` | `false` | 启用工单集成（对应 `ticketing.enabled`；需同时 `alerting.enabled: true`） |
| `TICKET_PROVIDER` | 空 | `jira` 或 `servicenow` |
| `TICKET_BASE_URL` | 空 | Jira/ServiceNow 基础地址，如 `https://jira.example.com` |
| `TICKET_USERNAME` | 空 | 服务账号用户名（Jira 可填邮箱） |
| `TICKET_PASSWORD` | 空 | Jira API token / ServiceNow 密码；**仅环境变量，不落配置** |
| `TICKET_PASSWORD_ENV` | `TICKET_PASSWORD` | 指定存放凭据的环境变量名（默认直接用 `TICKET_PASSWORD`） |
| `TICKET_TIMEOUT_SECONDS` | `15` | 建单/同步 HTTP 超时 |
| `TICKET_TLS_SKIP_VERIFY` | `false` | 跳过 TLS 证书校验（测试环境） |
| `TICKET_PROJECT` | 空 | Jira 项目 Key（如 `SEC`） |
| `TICKET_ISSUE_TYPE` | `Task` | Jira 问题类型名 |
| `TICKET_JIRA_ACK_TRANSITION_ID` | 空 | Jira ack 状态流转 ID；留空则仅添加评论 |
| `TICKET_JIRA_RESOLVED_TRANSITION_ID` | 空 | Jira resolved 状态流转 ID；留空则仅添加评论 |
| `TICKET_SERVICENOW_TABLE` | `incident` | ServiceNow 表名 |
| `TICKET_SERVICENOW_ACK_STATE` | `2` | ServiceNow ack 状态值 |
| `TICKET_SERVICENOW_RESOLVED_STATE` | `6` | ServiceNow resolved 状态值 |
| `SIEM_ENABLED` | `false` | 启用 SIEM/SOAR 事件流（对应 `siem.enabled`） |
| `SIEM_SPLUNK_HEC_URL` | 空 | Splunk HEC collector 地址 |
| `SIEM_SPLUNK_HEC_TOKEN` | 空 | Splunk HEC token；**仅环境变量，不落配置** |
| `SIEM_SPLUNK_HEC_TOKEN_ENV` | `SIEM_SPLUNK_HEC_TOKEN` | 指定存放 HEC token 的环境变量名 |
| `SIEM_SPLUNK_HEC_INDEX` | `main` | Splunk 索引 |
| `SIEM_SPLUNK_HEC_SOURCETYPE` | `vulnscan:events` | Splunk sourcetype |
| `SIEM_WEBHOOK_URL` | 空 | 通用 Webhook 地址（可选） |
| `SIEM_WEBHOOK_SECRET` | 空 | Webhook HMAC 签名密钥；**仅环境变量，不落配置** |
| `SIEM_WEBHOOK_SECRET_ENV` | `SIEM_WEBHOOK_SECRET` | 指定存放签名密钥的环境变量名 |
| `SIEM_DELIVERY_INTERVAL_SECONDS` | `10` | outbox 投递轮询间隔 |
| `SIEM_BATCH_SIZE` | `50` | 单批事件数（1-500） |
| `SIEM_MAX_ATTEMPTS` | `3` | 单批失败重试上限 |
| `SIEM_TIMEOUT_SECONDS` | `10` | 单次投递 HTTP 超时 |
| `SIEM_TLS_SKIP_VERIFY` | `false` | 跳过 TLS 证书校验（测试环境） |
| `CLOUD_SCAN_ENABLED` | `false` | 启用云资产接入（对应 `cloud_scan.enabled`） |
| `CLOUD_SCAN_MASTER_KEY` | 空 | AES-256 主密钥（hex/base64 32 字节），加密云账号凭据；**仅环境变量，不落配置** |
| `CLOUD_SCAN_MASTER_KEY_ENV` | `CLOUD_SCAN_MASTER_KEY` | 指定存放主密钥的环境变量名 |
| `CLOUD_SCAN_CONCURRENCY` | `2` | 云账号并发刷新数（1-16） |
| `CLOUD_SCAN_DEFAULT_REFRESH_INTERVAL_MINUTES` | `60` | 新建账号默认刷新周期 |
| `CLOUD_SCAN_TIMEOUT_SECONDS` | `30` | 单账号发现超时 |
| `WEBDB_SCAN_ENABLED` | `false` | 启用 Web 应用与数据库扫描（对应 `webdb_scan.enabled`） |
| `WEBDB_SCAN_MASTER_KEY` | 空 | AES-256 主密钥（hex/base64 32 字节），加密 Web/DB 扫描凭据；**仅环境变量，不落配置** |
| `WEBDB_SCAN_MASTER_KEY_ENV` | `WEBDB_SCAN_MASTER_KEY` | 指定存放主密钥的环境变量名 |
| `WEBDB_SCAN_TIMEOUT_SECONDS` | `10` | 单目标扫描超时 |
| `WEBDB_SCAN_CONCURRENCY` | `8` | 并发任务数（1-16） |
| `WEBDB_SCAN_TLS_SKIP_VERIFY` | `true` | 跳过 HTTP(S) TLS 证书校验（内网扫描默认开启） |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | 空 | 可选 LLM 分析 |
| `ADMIN_USERNAME` | `admin` | 首启控制台 admin 用户名（users 表为空时生效） |
| `ADMIN_PASSWORD` | 空 | 首启控制台 admin 密码；**生产必设**，不设置则控制台登录不可用（X-API-Key 通道不受影响） |

非容器部署仍可使用根目录 `server.yaml`（支持 `${ENV}` 展开），并可用 `VULNSCAN_CONFIG` 指定路径。

## 2. 安装 Agent / Install Agent

Server 镜像内已内置 4 个平台的 agent 安装包，通过 `/dl/agent/<platform>` 下载：
`linux-amd64`、`linux-arm64`、`windows-amd64.exe`、`windows-arm64.exe`。

### 2.1 生成注册命令

先用 API Key 获取一台 Agent 的安装命令（返回 `install_cmd` 与 `code`）：

```bash
curl -H "X-API-Key: $API_KEY" http://SERVER:8080/api/v1/agents/<agent-id>/install-command
```

注册码短期有效；脚本中的下载地址基于 `SERVER_URL` 生成，请确保其指向 Agent 可达的地址。

### 2.2 Linux

```bash
curl -fsSL http://SERVER:8080/r/<CODE> | bash
```

或手动安装：

```bash
curl -fsSL http://SERVER:8080/dl/agent/linux-amd64 -o /usr/local/bin/vuln-agent
chmod +x /usr/local/bin/vuln-agent
sudo /usr/local/bin/vuln-agent install <CODE> --server http://SERVER:8080
```

服务由 systemd 管理：`systemctl status vuln-agent`；卸载：`vuln-agent uninstall`。

### 2.3 Windows

```powershell
irm http://SERVER:8080/r/<CODE> | iex
```

或手动安装（管理员 PowerShell）：

```powershell
Invoke-WebRequest http://SERVER:8080/dl/agent/windows-amd64.exe -OutFile $env:TEMP\vuln-agent.exe
& $env:TEMP\vuln-agent.exe install <CODE> --server http://SERVER:8080
```

服务名为 `VulnAgent`：`sc query VulnAgent`；卸载：`vuln-agent.exe uninstall`。Agent 配置写入
`%USERPROFILE%\.vuln-scanner\agent.yaml`。

### 2.4 网络扫描（可选）/ Network Scanning (Optional)

在 `agent.yaml` 增加 `network_scan` 段即可启用 Agent 侧 TCP 发现与服务指纹（不登录主机）：

```yaml
network_scan:
  enabled: true
  interval_minutes: 60
  targets: ["192.168.10.0/24"]
  ports: [22, 80, 443, 445, 3389]
  exclude: ["192.168.10.99"]
  timeout_seconds: 2
  concurrency: 32
  max_hosts: 1024
```

结果上报 Server 后生成合成 agent（`agent-net-*`）并复用 CVE 匹配/风险/告警链路；也可通过
`POST /api/v1/network/scan` 下发一次性任务，任意 Agent 都会领取执行。

### 2.5 网络要求 / Network

- Agent → Server：TCP 9090（gRPC 遥测）与 8080（注册/下载/补丁任务）。
- 启用网络扫描的 Agent → 目标网段：TCP（目标端口，默认含 21/22/80/443/445/993/995/3306/3389/5432/6379/8080/8443）。
- Server → PostgreSQL：容器内网自动打通；本机部署请保持 5432 可达。
- Server → 公网：MSRC/NVD/OSV/Debian/Red Hat 数据源与（可选）LLM API。

## 3. 运维 / Operations

### 健康检查

`GET /health` 返回 200 即服务正常；compose 已配置 healthcheck，`docker compose ps` 可查看状态。

### 查看日志

```bash
docker compose -f deploy/docker-compose/docker-compose.yml logs -f server
```

### 备份与恢复

```bash
docker compose -f deploy/docker-compose/docker-compose.yml exec postgres \
  pg_dump -U ${POSTGRES_USER:-vulnscan} vulnscan > backup.sql
cat backup.sql | docker compose -f deploy/docker-compose/docker-compose.yml exec -T postgres \
  psql -U ${POSTGRES_USER:-vulnscan} -d vulnscan
```

数据持久化在 `pgdata` 命名卷中；`docker compose down` 保留数据，`docker compose down -v` 会删除数据。

### 升级

```bash
git pull
docker compose -f deploy/docker-compose/docker-compose.yml up -d --build
```

迁移在启动时自动执行；升级前建议先备份数据库。

## 4. 水平扩展 / Horizontal Scaling

单实例默认 `mode: all`，无需改动。需要扩容时，把职责拆成两类实例并共享同一 PostgreSQL：

| 拓扑 | 说明 |
| --- | --- |
| 1×all + N×worker | 现有单实例行为不变，再增加纯 worker 实例分担扫描与投递 |
| 1×api + N×worker | api 只提供 REST/gRPC 入口，所有后台循环由 worker 承担 |

- 模式配置：`server.yaml` 的 `mode`，或环境变量 `VULNSCAN_MODE`；每个实例都运行迁移（同一 `DATABASE_URL`，迁移幂等）。
- 后台机制（无新增消息中间件）：
  - `job_queue`：REST/Agent 触发的 match/cloud/container/工单/SIEM/远程/WebDB 唤醒统一入队，`FOR UPDATE SKIP LOCKED` 领取，`pg_notify` 即时唤醒 + 各循环轮询兜底；
  - `worker_leases`：feed、match 全量周期、scan_policy、sla、eol、report、container、archive、reap_patch 等单例循环由租约选举唯一持有者（心跳 10s、租约 30s，失联自动让渡）；
  - 并行循环（远程/WebDB/云/SIEM/工单/告警投递/单 Agent 匹配/自动修复）可在任意 worker 领取，重复执行遵循 at-least-once 语义（业务侧已幂等）。
- 配置一致性：所有实例必须使用相同 `DATABASE_URL`、`JWT_SECRET`、`API_KEY` 以及各主密钥（`REMOTE_SCAN_MASTER_KEY`/`CLOUD_SCAN_MASTER_KEY`/`WEBDB_SCAN_MASTER_KEY`）；SMTP/工单/SIEM 出站配置需在 worker 实例上生效。
- 网络要求：worker 实例需能访问外网数据源与 SMTP/工单/SIEM 等出站端点；api 实例需对外暴露 8080/9090。
- 观察：`GET /api/v1/workers`（admin）返回当前租约（loop/worker_id/hostname/pid/heartbeat age）与各 kind 的 pending 队列深度。
- 注意：
  - feed 租约持有者负责镜像内置情报并刷新外部数据源；`mode: api` 单独部署（无任何 worker）时不会同步内置情报与匹配，必须至少搭配一个 worker；
  - container 扫描依赖本机 Docker socket，仅在持有 container 租约且能访问 Docker 的实例上启用；
- 手工同步端点（报表发送、EOL/intel 刷新）采用“内联领取”：同一时刻只允许一个实例执行，其余返回 409。

## 4.1 多租户 v2 / Multi-tenant v2

租户 v2 把以下配置从“全局单份”改为“每租户独立行”，建租户时自动从租户 1 当前配置快照复制模板（快照语义，后续修改租户 1 不影响已建租户）：

- `alert_rules` 与 `sla_policies` 增加 `tenant_id`（默认 1）；alert 评估按 Agent 所属租户选规则，SLA 检查循环逐租户执行。
- `tenant_reports` 保存每租户报表的 `enabled/schedule/timezone/to`；`reporting.enabled` 与 `alerting.smtp` 仍为全局总开关/SMTP 配置。`reportLoop` 每 60 秒 reconcile 一次，仅当 `enabled/schedule/timezone/收件人` 变化时重建对应 cron，并按该租户收件人投递。
- 合成 Agent 按来源归属租户：远程继承 `remote_credentials.tenant_id`，云继承 `cloud_accounts.tenant_id`，WebDB 继承任务/凭据租户，网络继承上报 Agent 或任务租户，容器使用 `container_scan.tenant_id`（默认 1）。同一确定性 Agent ID 只保留首次扫描来源的租户。
- API key：新增 `api_keys` 表（仅存 SHA-256，明文创建时返回一次）。租户级 key 自动把请求限定到该租户，并收口为“租户内管理员”：可管理本租户数据、配置、凭据、扫描、告警规则、SLA 与 `/api/v1/tenants/{ownTenantId}/report` 及 `/report/send`；禁止 `/api/v1/tenants`、`/api/v1/users*`、`/api/v1/api-keys*`、`/api/v1/audit-logs*`、`/api/v1/workers*`、`/api/v1/admin/*`、`/tenant` 迁移端点及跨租户报表路径。`X-Tenant-ID` 若存在必须一致。全局 DB key 与旧全局 `api_key`（`API_KEY`/`server.yaml api_key`）继续作为全局 admin key 兼容。
- 全局管理入口（admin / 全局 key）：`GET/POST /api/v1/api-keys`、`DELETE /api/v1/api-keys/{keyId}`；租户报表 `GET/PUT /api/v1/tenants/{tenantId}/report`、`POST /api/v1/tenants/{tenantId}/report/send` 可由本租户管理员 key 访问自己的租户；全局手动发送仍为 `POST /api/v1/admin/report/send`。

## 5. Kubernetes（参考）/ Kubernetes (Reference)

`deploy/k8s/` 提供 namespace、ConfigMap/Secret、PostgreSQL StatefulSet 与 Server Deployment/Service 示例。
使用前必须：替换 Secret 中的占位值、将镜像改为已推送的 `ghcr.io/<owner>/vuln-scanner:<tag>`、按需调整 PVC 大小与副本数，
并配置 Ingress 或 LoadBalancer 暴露 8080/9090。

## 6. 故障排查 / Troubleshooting

- **server 反复重启、日志报 database connection failed**：确认 `POSTGRES_PASSWORD` 与 `DATABASE_URL` 一致、postgres 已 healthy。
- **`/health` 无响应**：查看 server 日志；确认 8080 端口未被占用。
- **Agent 安装脚本 404**：镜像未包含对应平台安装包或 `SERVER_URL` 指向错误；重新构建镜像（`docker compose build`）并核对 `SERVER_URL`。
- **Agent 注册成功但不上报**：确认 Agent 到 Server 的 9090 端口可达，`agent.yaml` 中 `server.addr` 指向正确 gRPC 地址。
- **Windows 服务启动失败**：先用前台模式 `vuln-agent.exe run` 查看报错，再安装服务。
- **数据源刷新慢**：设置 `NVD_API_KEY` 提速；刷新周期与 TTL 见 `server.yaml` 的 `cve` 段。
