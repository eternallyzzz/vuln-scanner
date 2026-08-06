# VulnScanner REST API 文档

VulnScanner 的 REST API 是控制台与自动化集成的主要入口；Agent 与 Server 之间的采集/任务通道使用
gRPC（规范见 [`api/proto/vulnscan/v1/agent.proto`](../api/proto/vulnscan/v1/agent.proto)，本文件不重复描述）。

## OpenAPI 规范

- 机器可读规范：`GET /openapi.yaml`（免鉴权）或仓库内 [`internal/server/openapi.yaml`](../internal/server/openapi.yaml)。
- 规范覆盖全部 REST 端点（`/health`、`/demo`、`/dl/*`、`/r/*`、`/api/v1/*`），包含路径/查询参数、鉴权方案、
  `x-roles` 角色标注、核心响应 schema 与错误码。
- v1 为「全路径 + 核心 schema」档位：约 15 个核心资源精确定义，其余复杂响应（如主机遥测、容器状态）以 `object` 描述。

## 鉴权

所有 `/api/v1/*` 端点（除 `/register`、`/auth/login`、`/auth/ldap/login`）二选一：

1. `X-API-Key: <key>`——admin 级自动化凭证，等价 admin 角色；
2. `Authorization: Bearer <jwt>`——用户登录返回的 JWT，按用户角色鉴权。

```bash
# 登录并保存 token
TOKEN=$(curl -s -X POST http://SERVER:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | jq -r .token)

# 带用户 token 调用
curl -s http://SERVER:8080/api/v1/compliance/summary -H "Authorization: Bearer $TOKEN"

# 或直接使用 API Key
curl -s http://SERVER:8080/api/v1/agents -H "X-API-Key: $API_KEY"
```

## 角色权限

| 角色 | 权限 |
| --- | --- |
| `admin` | 全部操作，含 `/admin/*`、用户管理、Agent 创建/删除、审计日志查询与导出、计划报表发送 |
| `operator` | 日常运维写操作：补丁任务/Campaign 流转、告警 ack/resolve/remediate、豁免创建/撤销、触发扫描/分析、资产导入与元数据、告警规则与 SLA 维护 |
| `viewer` | 只读（所有 GET；`/audit-logs*` 仅 admin 可见） |

公开端点（免鉴权）：`/health`、`/demo`、`/openapi.yaml`、`/dl/*`、`/r/*`、`/api/v1/register`、`/api/v1/auth/login`、`/api/v1/auth/ldap/login`。

每个操作的具体角色见 OpenAPI 规范中的 `x-roles` 扩展。

## 错误格式

错误响应统一为 JSON：

```json
{"error": "human readable message"}
```

常见状态码：

| 状态码 | 含义 |
| --- | --- |
| 400 | 参数或请求体不合法（如 RFC3339 时间、枚举值、窗口顺序） |
| 401 | 缺少或无效凭证；登录失败 |
| 403 | 当前角色无权访问 |
| 404 | 资源不存在或注册码无效 |
| 500 | 服务端内部错误 |

## 常用示例

```bash
# 查询活跃风险 Top（viewer 亦可）
curl -s http://SERVER:8080/api/v1/risk/top?limit=20 -H "X-API-Key: $API_KEY"

# 查询统一审计日志（仅 admin）
curl -s "http://SERVER:8080/api/v1/audit-logs?actor=admin&limit=50" -H "X-API-Key: $API_KEY"

# 导出合规评分 CSV
curl -s http://SERVER:8080/api/v1/compliance/export.csv -H "X-API-Key: $API_KEY"

# 手动发送计划报表（仅 admin）
curl -s -X POST http://SERVER:8080/api/v1/admin/report/send -H "X-API-Key: $API_KEY"

# 下发网络扫描任务（operator+；Agent 领取后执行）
curl -s -X POST http://SERVER:8080/api/v1/network/scan \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d '{"target":"192.168.10.0/24","ports":[22,80,443]}'

# 查看发现的主机
curl -s http://SERVER:8080/api/v1/network/hosts -H "X-API-Key: $API_KEY"

# 创建远程凭据（admin；auth_type=key 且不传 private_key 时响应一次性返回 public_key）
curl -s -X POST http://SERVER:8080/api/v1/remote/credentials \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"prod-linux","username":"scan","auth_type":"password","password":"..."}'

# 下发远程 SSH 扫描（operator+；Server 直连目标，默认端口 22）
curl -s -X POST http://SERVER:8080/api/v1/remote/scan \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  -d '{"credential_id":1,"targets":["192.168.10.21","192.168.10.22:2222"]}'

# 查看远程扫描任务与已采集主机
curl -s http://SERVER:8080/api/v1/remote/tasks -H "X-API-Key: $API_KEY"
curl -s http://SERVER:8080/api/v1/remote/hosts -H "X-API-Key: $API_KEY"

# 实时查看补丁任务执行事件（after 为游标，轮询时带上一次返回的 next_cursor）
curl -s "http://SERVER:8080/api/v1/patch-tasks/123/events?after=0" -H "X-API-Key: $API_KEY"

# 中止运行中的补丁任务（operator+；agent 心跳感知后终止进程树并上报 cancelled）
curl -s -X POST http://SERVER:8080/api/v1/patch-tasks/123/stop -H "X-API-Key: $API_KEY"
```

## 维护约定

- 新增/删除/修改 REST 路由时，必须同步更新 `internal/server/openapi.yaml`；`TestOpenAPIRoutesCovered`
  会双向校验路由清单，任何不一致都会让测试失败。
- 修改角色矩阵时同步更新 `x-roles` 标注与上表。
