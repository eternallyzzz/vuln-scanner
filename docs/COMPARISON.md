# VulnScanner 与商业漏洞管理软件对比 / Comparison with Commercial VM Platforms

> 更新日期：2026-08-05。对比对象：Tenable（Nessus / Tenable Vulnerability Management / Exposure）、
> Qualys VMDR（TruRisk）、Rapid7（InsightVM / Exposure Command）、Microsoft Defender for Cloud。
> 内容基于厂商公开资料与产品文档，评价为定性口径；符号：★ 支持 / ◐ 部分或受限 / — 暂不支持。

## 1. 定位与架构

| 维度 | VulnScanner | Tenable | Qualys VMDR | Rapid7 | Defender for Cloud |
| --- | --- | --- | --- | --- | --- |
| 交付形态 | 自托管开源（MIT），Agent/Server + PostgreSQL | SaaS / 本地扫描器 | SaaS / 云 Agent / 本地扫描器 | SaaS / 本地扫描器 | 云原生，绑定 Azure/Microsoft 生态 |
| 采集方式 | Agent（Windows/Linux）+ 本地容器扫描 | Agent + 网络扫描 + 被动监控 + 云 | Agent + 网络扫描 + 被动传感器 + 云 | Agent + 网络扫描 + 云 | Agent 扫描 + **agentless 快照扫描** |
| 适用规模 | 中小环境、内网/离线、国产化替代 | 企业级 | 企业级 | 企业级 | Azure/微软生态客户 |
| 数据落地 | 自有 PostgreSQL，数据自持 | 厂商云（本地扫描器仅数据采集） | 厂商云 | 厂商云 | Azure 云 |

## 2. 能力矩阵

| 能力 | VulnScanner | Tenable | Qualys VMDR | Rapid7 | Defender for Cloud |
| --- | --- | --- | --- | --- | --- |
| 主机资产发现（Agent） | ★ | ★ | ★ | ★ | ★ |
| Agentless/网络扫描 | — | ★ | ★ | ★ | ★（agentless 机器扫描） |
| 凭据认证扫描（远程主机） | — | ★ | ★ | ★ | ◐（主要 agent/agentless） |
| 云资产（AWS/Azure/GCP） | — | ★ | ★ | ★ | ★（原生） |
| AD/身份暴露面 | — | ★（Tenable One/AD 模块） | ◐ | ★ | ◐ |
| 系统漏洞多源匹配 | ★（MSRC/NVD/OSV/Debian/RH） | ★（Tenable Research 插件） | ★（Qualys ID） | ★（Nexpose 引擎） | ★（MDVM 信号） |
| SCA 软件成分 | ◐（npm/go/pypi/maven，无传递依赖图） | ★ | ★ | ★ | ★ |
| 容器镜像扫描 | ★（Trivy 本地镜像） | ★ | ★ | ★ | ★ |
| Web 应用扫描 | — | ★（Web App Scanning） | ◐（WAF/可选模块） | ★ | ◐ |
| 数据库/IoT/OT 扫描 | — | ★ | ★ | ★ | ◐ |
| CIS/合规基线 | ◐（Agent 侧 v1 精简子集：双平台各 10 项检查 + 合规评分/导出） | ★ | ★ | ★ | ★（CSPM 建议） |
| 配置错误/态势评估 | — | ★ | ★ | ★ | ★（CSPM） |
| EDR/恶意软件联动 | — | ◐（Tenable One） | ◐（联动） | ★（与 Insight Agent/EDR） | ★（MDE 原生） |
| CVSS 基础评分 | ★ | ★ | ★ | ★ | ★ |
| EPSS / KEV 情报 | ★ | ★ | ★ | ★ | ★ |
| 专有威胁优先级评分 | — | ★（VPR） | ★（TruRisk） | ★（风险评分） | ★（Secure Score） |
| 资产重要性/业务上下文 | ◐（标签/关键性/负责人/生命周期） | ★ | ★ | ★ | ★ |
| 可利用性验证 | — | ◐ | ★（TruRisk Eliminate 等） | ★（runtime validation） | ★（agentless 运行时） |
| 补丁建议 | ★ | ★ | ★ | ★ | ★ |
| 补丁执行/审批流 | ★（白名单模板+审批+窗口+dry-run） | ◐（第三方） | ★（FixIT/补丁管理） | ◐ | ★（Intune 集成） |
| 批量补丁 campaign | ★ | ◐ | ★ | ◐ | ◐ |
| 工单集成（Jira/ServiceNow） | — | ★ | ★ | ★ | ★ |
| 风险豁免/异常管理 | ★ | ★ | ★ | ★ | ★ |
| 修复验证 | ◐（WUA/WSUS 事实 + 已装 KB） | ★（重扫） | ★（重扫/传感器） | ★（重扫） | ★（agentless 重扫） |
| 风险仪表盘/趋势/SLA | ★ | ★ | ★ | ★ | ★ |
| 计划报表/邮件订阅 | ●（cron 调度 CSV/HTML 全景日报 + SMTP 投递） | ★ | ★ | ★ | ★ |
| 审计日志查看 | ●（统一 `audit_logs`：写操作自动记录 + admin 查询/CSV 导出） | ★ | ★ | ★ | ★ |
| REST API | ★ | ★ | ★ | ★ | ★ |
| Webhook 出站 | ★（告警 HMAC） | ★ | ★ | ★ | ★ |
| SIEM/SOAR 集成 | ◐（可经 webhook 转发） | ★ | ★ | ★ | ★ |
| SSO/LDAP | — | ★ | ★ | ★ | ★（Entra ID） |
| RBAC 多用户 | ◐（本轮新增 admin/operator/viewer） | ★ | ★ | ★ | ★ |
| 多租户/MSP | — | ★ | ★ | ★ | ◐ |
| 离线/内网部署 | ★（完全自托管） | ◐ | ◐ | ◐ | — |

## 3. 数据源与检测质量

- **VulnScanner**：MSRC（CVRF 每产品 KB）、NVD、OSV（Debian/Alpine/Ubuntu/Alma/Rocky/SUSE/RH + 语言生态）、
  Debian Security Tracker、Red Hat Security Data，并融合 EPSS/KEV。匹配语义借鉴 Wazuh（版本比较器、包翻译、
  热补丁判定），已建立全链路 fixtures 准确率基线（`internal/cve/testdata/accuracy/`，16 个场景）。
- **Tenable**：Tenable Research 漏洞情报 + Nessus 插件体系，覆盖专有系统、OT、Web 应用；AI 驱动的漏洞情报。
- **Qualys VMDR**：Qualys ID 指纹与专有检测（官方宣称 Six Sigma 级准确率），覆盖网络/云/OT。
- **Rapid7**：Nexpose 扫描引擎 + Metasploit 验证，强调"检测 + 可利用性验证"。
- **Defender for Cloud**：Microsoft Defender 漏洞管理信号，agentless 快照 + 代理双通道，深度绑定微软遥测。

诚实结论：商业产品在检测覆盖广度（专有软件、Web/DB/OT、配置基线）与威胁情报时效上明显更强；
VulnScanner 在主流操作系统包与 Windows 补丁场景可对标，且具备可离线、可解释、可测试的确定性匹配，
但缺少网络扫描、认证验证与专有情报渠道。

## 4. 风险评分对比

| 产品 | 评分机制 | 说明 |
| --- | --- | --- |
| VulnScanner | `CVSS×0.40 + EPSS×0.25 + 资产关键性×0.20 + 暴露度×0.15`，KEV 保底 9.0 | 权重固定、可解释；无专有威胁情报 |
| Tenable VPR | 威胁强度/影响/可利用性 + 威胁情报 | 1-10 分，动态 |
| Qualys TruRisk | 多因子（漏洞、资产、威胁情报、业务上下文） | 支持按业务关键性自动化修复（FixIT） |
| Rapid7 | 资产/漏洞/威胁情报综合评分 | 与 Metasploit 验证联动 |
| Defender Secure Score | 控制项完成度 + 风险建议 | 组织级态势分，非单漏洞分 |

VulnScanner 可借鉴的方向：分层可解释权重（已具备雏形）、威胁情报因子可配置、资产业务上下文加权
（标签/关键性已支持，可进一步接入 EOL 与暴露面）。

## 5. 差距分级与路线图

### P0（安全与合规基础）
- [x] RBAC 多用户：admin/operator/viewer、登录 JWT、用户管理、操作人审计回填（2026-08 完成）

### P1（近期补齐，单轮范围可控）
- [x] 审计日志：统一写操作自动记录 + admin 查询/CSV 导出（2026-08 完成）
- [x] EOL/停更检测：OS 与发行版生命周期纳入风险评分与报表（2026-08 完成）
- [x] 计划报表：cron 式调度 CSV/HTML 报告 + SMTP 投递（2026-08 完成）
- [x] CIS/合规基线：Agent 侧配置检查与合规评分（2026-08 完成）
- [x] OpenAPI 规范与 API 文档（2026-08 完成）

### P2（中期）
- Agentless/网络扫描与凭据认证扫描（范围大，需单独设计）
- 工单集成（Jira/ServiceNow）与 SIEM/SOAR 事件流
- SSO/LDAP（对接已有 RBAC）
- 云资产接入（AWS/Azure/GCP 凭据发现）
- Web 应用与数据库扫描

### P3（远期）
- 多租户/MSP 与水平扩展（消息队列、分布式 worker）
- EDR/恶意软件联动与运行时验证
- 专有威胁情报与更细的漏洞指纹体系

## 6. 定位建议

VulnScanner 的差异化不是与商业巨头正面竞争，而是：

1. **全链路开源、数据自持**：适合内网/离线、数据合规敏感、中小规模环境；
2. **确定性匹配 + 可测试基线**：匹配语义可解释、可回归，优于商业黑盒；
3. **补丁闭环完整**：审批、执行窗口、批量 campaign、dry-run 演练与审计，贴近日常运维；
4. **轻量部署**：单容器 + PostgreSQL 即可上线，运维成本远低于商业套件。

短板按 P1→P2 优先级补齐后，可在"开源漏洞管理平台"定位上与 Wazuh 形成互补（Wazuh 偏 HIDS/XDR，
VulnScanner 偏资产管理 + 漏洞治理 + 补丁闭环）。
