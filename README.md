# VulnScanner

Server/Agent 架构的资产漏洞扫描与管理平台：资产采集（Windows/Linux/SCA）→ CVE 匹配（MSRC/NVD/OSV/Debian）→ 告警 → 补丁建议与执行 → CMDB 资产台账，形成扫描-告警-修复-deploy 闭环。

## 架构

- `cmd/server`：REST（:8080，X-API-Key 鉴权）+ gRPC（:9090，JWT 鉴权）+ PostgreSQL
- `cmd/agent`：资产采集与上报，支持 Windows/Linux，可安装为系统服务
- `internal/store`：Postgres 访问与迁移（`migrations/*.up.sql` 启动自动执行，只增不改）
- `internal/cve`：漏洞源加载与确定性匹配
- `internal/alert`：告警规则求值、去重/冷却、Webhook/SMTP 投递
- `internal/patch`：补丁命令模板（白名单）与部署配置

## 配置（server.yaml）

```yaml
alerting:
  enabled: true
  webhook_url: "https://hooks.example.com/x"
  webhook_secret: "hmac-secret"
  smtp: { host: "", port: 587, user: "", password_env: SMTP_PASSWORD, from: "", to: [] }
  delivery_interval_seconds: 30
  max_attempts: 3
patch:
  enabled: true
  default_approval_required: true
  agent_timeout_seconds: 600
  apt_command: "apt-get install -y --only-upgrade"
  dry_run: true   # true=只记录不执行，上线前先演练
  auto_remediation:
    enabled: true          # 新告警命中 auto_remediate 规则时自动生成补丁 campaign
    approval_required: true
    min_severity: HIGH
    max_campaigns_per_hour: 50

container_scan:
  enabled: true
  docker_host: "unix:///var/run/docker.sock"
  images: []               # 空 = 扫描全部本地镜像；可显式列出 repo:tag
  image_filter: ""         # 可选正则过滤镜像
  exclude: ["kicbase", "docker-desktop"]
  trivy_image: "aquasec/trivy:latest"
  trivy_cache_volume: "vulnscan-trivy-cache"
  agent_id: "agent-container-docker"
  scan_interval_minutes: 360
  timeout_minutes: 20
  max_images: 100
```

Agent 侧：`~/.vuln-scanner/agent.yaml` 中 `agent.patch_enabled: true` 开启补丁任务轮询。

## 核心 API

- 资产：`GET/PUT /api/v1/assets...`（筛选、标签/环境/负责人、生命周期、变更历史、关系、summary）
- 告警：`/api/v1/alert-rules` CRUD、`/api/v1/alerts` 查询/ack/resolve/remediate、`test` 通道测试；规则支持 severity/source/agent/asset/tag/environment/min_cvss/cooldown，`auto_remediate: true` 时新告警自动生成补丁 campaign（告警上回填 remediation_campaign_id）
- 补丁：`POST /agents/{id}/patch-tasks/generate`、`/patch-tasks/{id}/approve|reject|cancel|retry`；agent 轮询执行并回传结果
- 批量补丁：`POST /api/v1/patch-campaigns`（按 agent_ids/tags/environments/asset_names/cve_ids/min_severity/min_cvss 批量生成，支持 `dry_run` 预演、重复任务去重）、`/patch-campaigns/{id}/approve|reject|cancel|retry` 批量状态流转、`/patch-campaigns/{id}` 汇总与审计、`GET /api/v1/patch-tasks` 全局任务列表
- 容器扫描：`POST /api/v1/container/scan` 异步触发 Trivy 扫描、`GET /api/v1/container/status` 扫描状态、`GET /api/v1/container/images` 镜像清单；结果落入合成 agent（默认 agent-container-docker），修复建议为 rebuild（不可自动部署）
- 资产元数据：`POST /api/v1/assets/bulk-meta` 批量维护 tags/environment/business_unit/owner/lifecycle
- 扫描：`/api/v1/scan-policies`、`POST /agents/{id}/scan`
- 漏洞：`/agents/{id}/vulns`、`/recommendations`、`/report`、`/dashboard`、`/search`、`/stats`

## 安全模型

- 补丁命令由服务端白名单模板生成（apt argv 数组 / 受限 PowerShell 脚本），资产名与 URL 均校验，杜绝自由 shell 输入
- 任务默认需审批，且受执行窗口约束；agent 仅领取 approved 且在窗口内的任务
- 执行结果（exit_code/output/时间）与审批人全部落库审计；`dry_run` 可安全演练
- 告警投递带 HMAC-SHA256 签名，投递失败最多重试 3 次并留痕

## 开发

```bash
make proto          # 重新生成 gRPC 代码（需 protoc + protoc-gen-go）
make build          # 构建 server/agent
make test           # 单测
go run ./cmd/server # 本地运行（依赖 PostgreSQL）
```

## 数据源与已知限制

- CVE 数据源：MSRC、NVD、OSV（Debian/Alpine/Ubuntu/AlmaLinux/Rocky Linux/SUSE/Red Hat 及语言生态）、Debian Security Tracker、Red Hat Security Data（列表 + per-CVE package_state 详情）。
- Ubuntu 主机通过 OSV 官方记录覆盖 CVE/USN/LSN，生态名按版本映射（如 `Ubuntu:22.04:LTS`）。
- Red Hat package_state 的未修复状态（Affected / Will not fix / Fix deferred / Under investigation）只对真实 RHEL agent 生效；AlmaLinux/Rocky/CentOS 不继承该判定，避免误报。
- CentOS Stream 与 Fedora：OSV 无覆盖（生态列表与数据目录均无），CentOS Stream 保持显式跳过 RHEL 数据匹配，Fedora 无专门数据源；Arch 不支持。
