# 闭环质量审计报告（资产匹配 → CVE → 补丁 → 复扫验证）

- 日期：2026-08-07
- 范围：只读审计，未修改业务代码、未写数据库
- 关注点：资产→CVE 匹配（防误报/漏报）、CVE→补丁完整性（防补丁不全/漏保）、匹配数据源补强（Ubuntu/Alpine/Amazon Linux）、补丁后复扫闭环

---

## 1. 结论摘要

当前“匹配准确率”在语料快照上表现很好（42 个 fixture，TP=36 / FP=0 / FN=0，P=R=F1=1.0），但这只证明**已有语料覆盖的场景**不误报、不漏报，不能证明真实数据集的召回。真实数据上存在三类系统性缺口：

1. **补丁完整性**：补丁任务模型是“单资产 + 单修复值 + 单条命令”，无法表达“修复 A 还必须升级/安装 B”这类依赖关系，是当前最大的漏保风险。
2. **数据源覆盖**：当前库中 Ubuntu/Alpine/Amazon Linux 没有原生源（Ubuntu 依赖 OSV 按包查询、Alpine/Amazon 基本靠 OSV/NVD 兜底），真实召回不足。
3. **可见性**：不可部署的 KB 任务（当前数据卷中 `kb_downloads` 为空）在生成阶段被静默跳过，只有计数没有明细，用户看到“补丁已报告”但实际永远无法下发。

建议按“先补可见性 → 再补数据源 → 最后做补丁依赖闭包”的顺序推进，详见第 7 节。

---

## 2. 审计范围与方法

- 通读匹配、推荐、campaign 生成、命令构建、post-patch 验证相关代码；
- 核对 `internal/cve/testdata/accuracy/snapshot.json` 基线并运行 `go test ./internal/cve -run 'TestAccuracy'`（通过）；
- 统计 2026-08-07 备份卷（`backups/vulnscan-4b802267-20260807-144421.sql`，本机 PG14 项目库）的表数据分布；
- 网络验证候选数据源可达性（Canonical OVAL、Alpine secdb、Amazon ALAS、OSV API）。

审计只读，未启动/停止任何容器，未占用端口，未修改数据库。

---

## 3. 当前闭环架构与基线

### 3.1 闭环链路

```text
Agent 采集资产快照
        │
        ▼
Loader.RefreshAllOSV / Debian / MSRC / NVD / Red Hat 抓取 ──► cve_feed
        │
        ▼
Matcher.MatchAssets（按 source 顺序 debian→msrc→redhat→nvd→osv→custom）
        │  同名 CVE+asset 用 sourceRank/betterMatch 去重
        ▼
SaveResults ──► cve_results（active/fixed）
        │
        ▼
GetAgentRecommendations（按 asset 聚合）+ GetKBPatchRecommendations（按 asset+KB 分组）
        │
        ▼
runCampaignGeneration（每 asset/每 KB 生成任务）──► patch_tasks
        │  命令由 BuildCommandForAgent 生成，Deployable=false 则静默跳过
        ▼
Agent 执行 ──► CompletePatchTask：status=success 时 post_patch_status=pending
        │
        ▼
下一次 runSingleMatch ──► SaveResults 后 VerifyPendingPostPatchTasks
        │  任务自身 cve_ids 已无 active 记录 → passed；仍有 → failed
        ▼
ReapStalePostPatchVerifications：24 小时未复扫 → failed
```

关键位置：

- 匹配源顺序与去重：`internal/cve/feed.go:343`（`MatchAssets`）、`internal/cve/feed.go:360`（`sourceOrder`/`sourceRank`/`betterMatch`）
- OSV 抓取：`internal/cve/loader.go:78`（`RefreshAllOSV`）、`internal/cve/osv.go:104`（`QueryPackages`）
- 推荐：`internal/store/cve.go:261`（`GetAgentRecommendations`）、`internal/store/cve.go:341`（`GetKBPatchRecommendations`）、`internal/store/cve.go:398`（`ActiveCVEsByAssetFiltered`）
- 任务生成：`internal/server/campaign_service.go:81`（`runCampaignGeneration`）
- 命令构建：`internal/patch/template.go:45`（`BuildCommandForAgent`）、`internal/patch/template.go:50`（`buildCommand`）
- 复扫验证：`internal/store/patch.go:200`（`CompletePatchTask`）、`internal/store/patch.go:326`（`postPatchVerdict`）、`internal/store/patch.go:402`（`VerifyPendingPostPatchTasks`）、`internal/server/worker.go:667`（`runSingleMatch`）

### 3.2 准确率基线

`internal/cve/testdata/accuracy/snapshot.json`（`TestAccuracySnapshot` 校验）：

| 指标 | 值 |
|---|---|
| fixture 数 | 42 |
| verdict 记录数 | 36 |
| TP / FP / FN | 36 / 0 / 0 |
| Precision / Recall / F1 | 1.0 / 1.0 / 1.0 |

注意：该快照是**受控语料**，主要覆盖名称/别名归一、版本比较、MSRC KB 匹配、跨源去重等单点场景。它不能证明：真实 Ubuntu/Alpine/Amazon 资产的召回、补丁依赖完整性和 KB 可部署性。

### 3.3 数据现状（备份卷统计）

| 表 | 行数 | 说明 |
|---|---|---|
| cve_feed | 43,005 | debian 325 / msrc 27,108 / redhat 7,900 / osv 7,604 / nvd 68 |
| cve_results | 2,648 | active 2,340 / fixed 308；来源 debian 251 / redhat 419 / osv 1,064 / trivy 913 / msrc 1 |
| assets | 6,089 | agent 上报 6,085 / cmdb_import 4 |
| patch_tasks | 23 | 历史任务少，说明真实闭环样本有限 |
| kb_metadata | 2,368 | KB 链接元数据 |
| kb_downloads | 0 | **没有一条带 SHA256 的直接下载记录** |
| cve_alias | 688 | backfill 644 / osv 44 |
| package_translations | 4,651 | 包名翻译/归一 |
| custom_intel | 7 | 自定义情报 |
| os_lifecycle | 40 | 系统生命周期 |

三个明显信号：

- `cve_feed` 中没有任何 `ubuntu` / `alpine` / `amazon` 原生 source；Ubuntu 只能靠 OSV 的 `Ubuntu:*` ecosystem 记录覆盖，Alpine 靠 `Alpine:v*`，Amazon 基本没有可靠来源。
- `kb_downloads=0`：结合命令构建逻辑，当前所有 Windows KB 任务都会变成“manual download required / host not allowed”，在 campaign 生成阶段被跳过。
- 真实闭环样本（patch_tasks=23）太少，post-patch 验证的 passed/failed 分布尚不足以说明问题，但代码审计已能定位结构性缺口。

---

## 4. 问题清单

### 4.0 总览

| 编号 | 优先级 | 问题 | 影响 |
|---|---|---|---|
| P0-1 | P0 | 补丁模型无法表达“修复 A 依赖 B” | 漏保：报告补丁 A 但实际未修好；复扫必然 failed |
| P0-2 | P0 | 版本类推荐按 asset 聚合、固定版本取 MAX，CVE 与修复值未精确绑定 | 任务 CVE 列表含无关 CVE；复扫误报/混报 |
| P1-1 | P1 | Windows KB 自动部署门槛过高，`kb_downloads` 为空时全部被静默跳过 | 报告有补丁但永远无法下发，且无明细 |
| P1-2 | P1 | Ubuntu/Alpine/Amazon 原生数据源缺失，Ubuntu 召回受“按当前包名查询 OSV”限制 | 真实资产漏报，尤其是非当前采集清单内的包 |
| P2-1 | P2 | campaign 只返回 skipped 计数，不返回不可部署/去重明细 | 排障成本高，用户不知道“为什么没生成任务” |
| P2-2 | P2 | sourceOrder/sourceRank 硬编码，新源接入需要同步修改并有回归测试 | 接入新源后可能出现去重优先级错误 |
| P2-3 | P2 | post-patch 验证只按“同 asset 的 cve_ids 是否还 active”判定 | 与补丁闭包不配套时产生噪音失败；无法给出“还缺哪个组件” |
| P3-1 | P3 | 报告/API 对“补丁完整性”表达不足（无依赖、无前置条件字段） | 人工审核无法判断补丁是否齐全 |

### 4.1 P0-1 补丁模型无法表达“修复 A 依赖 B”

**证据**

- `internal/patch/template.go:50` 的 `buildCommand`：`version` 分支只生成
  `apt-get install -y --only-upgrade <assetName>` / `dnf -y update <assetName>` / `apk upgrade <assetName>`；
  `kb` 分支只下载并安装**单个** `.msu`；`rebuild` 分支纯提示。
- `internal/server/campaign_service.go:232`：生成任务时只传 `rec.FixType / rec.FixedVersion / rec.AssetName` 一个修复值。
- 数据模型：`cve_results.fixed_version` 是单值（`internal/store/migrations/004_cve_results.up.sql`），`patch_tasks` 只有单 `fix_type` / `fix_value` / `cve_ids`（`009_patch_tasks.up.sql`），没有“补丁闭包/依赖集合”字段。

**根因**

“该 CVE 的修复”被建模成“某个资产升到某个版本/装某个 KB”的单一动作，而真实世界常见：

- 一个 USN/DSA 公告同时修复多个包（例如 samba 修复连带 libldb2、libsmbclient）；
- 包改名/拆包（libssl1.1 → libssl3、curl → libcurl4 等）；
- KB 有前置依赖或需要 Servicing Stack Update；
- `apt-get --only-upgrade` / `apk upgrade` 只升级已安装的指定包，不会安装“修复所需的另一个新包”。

**影响**

- 报告“补丁 A”但实际未修复 → 漏保；
- 补丁后复扫会把这类任务判为 `failed`，方向正确，但当前没有后续机制把它转换成“升级 B”的新任务，只会积累失败；
- 如果修复实际在 B 包而任务只写了 A，用户在 B 上手工修复后，A 任务依然被标记 failed（误报噪音）。

**建议**

引入“补丁闭包”概念：一条任务由主修复 + 一组必需依赖修复组成，命令可生成多条 argv；依赖来源采用静态规则表（见第 5 节）。post-patch 验证按闭包覆盖的 CVE 判定，failed 时输出“仍缺哪些组件/依赖”的机器可读建议。

### 4.2 P0-2 版本类推荐按 asset 聚合，CVE 与修复值未精确绑定

**证据**

- `GetAgentRecommendations`（`internal/store/cve.go:261`）SQL：
  `GROUP BY r.asset_name`，固定版本取 `COALESCE(MAX(NULLIF(r.fixed_version,'')),'')`。
- `ActiveCVEsByAssetFiltered`（`internal/store/cve.go:398`）只返回 `asset_name → cve_id[]`，没有返回每个 CVE 对应的修复值。
- `runCampaignGeneration`（`internal/server/campaign_service.go:81`）把整个 asset 的 CVE 数组绑到一条任务上。

**根因**

KB 路径已经按 `(asset, kb)` 分组（`GetKBPatchRecommendations`），但版本路径仍按 `asset` 聚合：一个资产有多个 CVE、多个来源、多个 `fixed_version` 时，MAX 只取其中一个，任务的 `cve_ids` 却包含全部。

**影响**

- 若同一资产两个 CVE 的修复版本不同（例如一个 1.2.3、一个 2.0.0），任务只声明“>= 2.0.0”但 CVE 列表包含 1.2.3 那个，语义不精确；
- 来源竞争时（debian 给 A 版本、OSV 给 B 版本），MAX 的结果可能与实际生效的源不一致；
- post-patch 复扫按任务 `cve_ids` 判定，会把这些 CVE 混在一起判定。

**建议**

版本类推荐也按 `(asset, fix_value)` 分组（仿 KB 路径），`cve_ids` 只绑定该修复值实际覆盖的 CVE；`ActiveCVEsByAssetFiltered` 改为返回 `asset → (fix_value → cve_ids)`，或在任务生成时用“CVE → 其来源 fixed_version”精确过滤。

### 4.3 P1-1 Windows KB 自动部署门槛过高，当前数据全部被静默跳过

**证据**

- 备份卷：`kb_metadata=2,368`、`kb_downloads=0`。
- `internal/server/msrc_links.go:53`（`enrichKBLinks`）：`PatchURL = bestPatchURL(...)`；`bestPatchURL` 在没有 verified download 时回退到 support 页或 Update Catalog 搜索页。
- `internal/patch/template.go:50` 的 `kb` 分支：只允许
  `download.microsoft.com`、`catalog.s.download.microsoft.com`、`catalog.s.download.windowsupdate.com`、`aka.ms`、`go.microsoft.com`；
  `catalog.update.microsoft.com` 与 `support.microsoft.com` 都不在 allowlist → 返回
  `manual download required (host not allowed)` → `Deployable=false`。
- `internal/server/campaign_service.go`（约 178-200 行）：`!cmd.Deployable` 时只 `skippedNonDeployable++`，不创建任务、不记明细。

**根因**

“可自动部署”被严格定义为“有官方下载域名 + SHA256 校验”，这是正确的安全底线；但当前 `kb_downloads` 没有任何数据，同时回退链接又不满足 allowlist，导致所有 KB 任务在生成阶段被丢弃，且没有任何告警或任务记录。

**影响**

- Windows 资产“有 KB 推荐”但永远无法自动修复，用户看到的是计数而不是具体哪个 KB 缺下载；
- 若只依赖人工手工下载，报告里也没有醒目标记；
- 这属于典型的“报告补丁不全/漏保”场景。

**建议**

1. 短期：把 `skipped_non_deployable` 明细（asset/KB/原因）写入 campaign 结果和 SIEM 事件，推荐 API 增加“不可自动部署”状态；
2. 中期：补全 `kb_downloads` 数据链路（迁移 047 已建表，`internal/server/kb_downloads.go` 已有查询/选择逻辑），为 KB 提供带 SHA256 的官方直链；
3. 长期：区分“可自动修复 / 可手动修复 / 无可用补丁”三种状态，报告和任务列表都展示，避免静默跳过。

### 4.4 P1-2 Ubuntu/Alpine/Amazon Linux 原生数据源缺失

**证据**

- `cve_feed` 源分布：debian 325、msrc 27,108、redhat 7,900、osv 7,604、nvd 68，**没有 ubuntu/alpine/amazon source**。
- OSV 抓取是“按当前资产包名查询”（`internal/cve/loader.go:78` `RefreshAllOSV` → `internal/cve/osv.go:104` `QueryPackages`），只覆盖**当前 agent 快照里出现的包**；不在任何快照中的包不会进入 `cve_feed`。
- 匹配层已经有 Ubuntu/Alpine 的 ecosystem 处理（`internal/cve/feed.go` `isRelevantProduct` 的 `Ubuntu:*` / `Alpine:v*` 分支、`internal/cve/loader.go:757` `OSVEcosystemForAgent`、`internal/cve/apkver.go` Alpine 版本比较），说明匹配逻辑就绪，缺的是**全量、权威的源数据**。
- Amazon Linux：snapshot 里有 `linux-amazon-openssh` fixture 且通过，但依赖的是手工/OSV 数据，没有稳定来源。

**根因**

项目只接了 Debian、MSRC、Red Hat、NVD、OSV、custom 六类源；Ubuntu/Alpine/Amazon 的权威数据（Canonical OVAL、Alpine secdb、Amazon ALAS）没有被纳入，Ubuntu 只能借用 OSV，Alpine/Amazon 几乎靠通用源兜底。

**影响**

- 真实 Ubuntu/Alpine 资产漏报：只有“已采集包 + OSV 有记录”才可能命中；
- 通用源（NVD/OSV 非 distro 记录）在版本语义上可能误判（例如 Ubuntu 只在特定 release 修复、Debian patch level 带 `+deb12u1` 后缀）；
- 新增资产或新包后，召回依赖下一次 OSV refresh，时效性差。

**建议**

按第 6 节评估接入：Alpine secdb（成本低、收益大）、Canonical OVAL/OSV 全量（成本中、收益大）、Amazon ALAS（先验证 OSV 覆盖，再做页面/第三方评估）。

### 4.5 P2-1 campaign 只返回 skipped 计数，没有明细

**证据**

`runCampaignGeneration` 的 `res.Counts` 只含 `matched / skipped_dedup / skipped_non_deployable` 三个数字；`dry-run` 只输出 `plans`（matched），被跳过的没有逐条明细；错误只以 `buildErrors` 聚合。

**建议**

返回 `skipped[]`（含 agent/asset/KB/原因/建议动作），dry-run 和实际生成都展示；同时写 SIEM 事件。

### 4.6 P2-2 sourceOrder/sourceRank 硬编码

**证据**

`internal/cve/feed.go:360-441`：`sourceOrder = ["debian","msrc","redhat","nvd","osv","custom"]`，`sourceRank` 把 debian/redhat/osv/msrc 视为原生源，nvd/custom 视为通用源；`betterMatch` 依赖这两个函数。

**影响**

将来加 `ubuntu` / `alpine` / `amazon` 原生源后，如果不更新 `sourceOrder`/`sourceRank`，同一 CVE+asset 的去重可能继续偏向 OSV 或 NVD，导致 fixed_version/状态不是发行版原生语义。

**建议**

把“源优先级”改为数据驱动（如配置表或常量映射），并为“同 CVE 多源去重”增加专项测试（`debian vs ubuntu`、`ubuntu vs osv`、`alpine vs nvd`、`amazon vs osv`）。

### 4.7 P2-3 post-patch 验证与补丁闭包不配套

**证据**

- `activeCVEsForPatchTask`（`internal/store/patch.go:373`）：`WHERE agent_id=$1 AND asset_name=$2 AND status='active' AND cve_id = ANY($3)`；
- `postPatchVerdict`（`internal/store/patch.go:326`）：任务无 CVE → na；剩余为空 → passed；否则 failed。

**影响**

- 当前实现能可靠暴露“任务升级了 A 但 CVE 仍 active”的漏保（这是好事）；
- 但无法区分“A 确实没修好”与“修好 A 需要 B”两种情况，failed detail 只有剩余 CVE 列表，没有“缺哪个组件/依赖”；
- 若用户手工在 B 上修复，A 任务仍会被判 failed（同 asset 才查，B 不同 asset 时剩余为空？实际上 A 的 CVE 仍 active 在 A 资产下，所以仍 failed）。

**建议**

引入 fix set 后，验证按“任务声明的补丁闭包覆盖哪些 CVE”判定；failed 时输出依赖建议（由规则表推导）。`remaining_cves` 已随 SIEM 事件输出，可扩展为 `missing_fixes`。

### 4.8 P3-1 报告/API 缺少补丁完整性表达

**证据**

`FixRecommendation`/`KBPatchRecommendation`（`internal/store/cve.go:220-258`）只有单 `PatchURL`/`PatchSHA256`/`ReferenceURL`，KB 有 `Links`；Linux 版本类没有“该修复还涉及哪些包”。HTML 报告直接渲染这些字段。

**建议**

在推荐模型和 REST 响应中增加 `fix_set` / `dependencies` / `prerequisites`，报告中增加“补丁完整性/依赖”区块。

---

## 5. 静态补丁依赖规则设计草案（本轮只设计，不改代码）

### 5.1 目标

把“修复 A 还需要 X/Y”从人工判断变成可生成、可验证、可报告的结构化数据，最终让 `patch_tasks` 表达**补丁闭包**，而不是单条命令。

### 5.2 数据模型建议

```text
FixDependency {
    AssetName  string   // 依赖的目标资产/包（如 libldb2、libssl3、SSU KB）
    FixType    string   // version | kb | rebuild
    FixValue   string   // 目标版本或 KB 号
    Required   bool     // true=必须；false=建议/前置提示
    Reason     string   // 规则来源：advisory | rename | prerequisite | same_advisory
    SourceRef  string   // 证据链接（USN/DSA/公告）
}

PatchFix {                     // 一条补丁闭包
    AssetName    string
    FixType      string
    FixValue     string
    CVEIDs       []string
    Dependencies []FixDependency
}
```

落地时 `patch_tasks` 增加 `fix_set JSONB`（或 `dependencies JSONB`），`cve_results` 可增加 `fix_set_hash` 便于分组与去重；`Commands [][]string` 已存在，天然支持“多条命令”。

### 5.3 静态规则来源

| 规则类型 | 例子 | 数据来源 |
|---|---|---|
| advisory 多包 | USN 同时修 samba + libldb2 + libsmbclient | Ubuntu USN 元数据 / Canonical OVAL affected 包集合 |
| 包改名/拆包 | libssl1.1 → libssl3；curl → libcurl4 | `package_translations` + 发行版公告 fixed 包 |
| KB 前置/SSU | 安装某累积更新前需先装 SSU | MSRC/Update Catalog 元数据（人工种子 + 校验） |
| 同 CVE 多包修复 | nss 与 nss-util 同公告 | 发行版 advisory 的 fixed 包列表 |
| 容器重建提示 | 镜像需 rebuild | 现有 rebuild 分支，保持 advisory-only |

规则表可以先用代码内静态表（`internal/patch/deps.go`）+ 少量 SQL 种子，后续再演进为配置/DB 表。规则必须带 `SourceRef`，便于审计。

### 5.4 生成、去重与验证改动点

1. **推荐层**：`GetAgentRecommendations` 增加可选 `ExpandFixSet`，输出主修复 + 依赖修复；KB 分组逻辑保持不变，扩展 `Prerequisites`。
2. **命令层**：`BuildCommandForAgent` 增加接受 `[]PatchFix` 的重载，version 类生成多条 `argv`（如先升级依赖 B，再升级 A），KB 类可先装前置 KB 再装目标 KB；`Display` 展示完整闭包。
3. **去重**：`HasOpenPatchTask` 的键从 `(agent, asset, fix_value)` 改为 `(agent, fix_set_hash)`；空 fix_set 回退旧行为，避免破坏现有任务。
4. **循环检测**：依赖图构建时 DFS 判环；自依赖直接拒绝；规则表加载时做静态校验（不允许 A→B→A）。
5. **验证**：`postPatchVerdict` 增加“闭包覆盖集”参数：任务 CVE 若全部不再 active → passed；若仍有 active → failed，并输出 `missing_fixes`（由剩余 CVE 反查依赖规则得到候选组件）。
6. **报告**：`FixRecommendation`/`PatchTask` 暴露 `dependencies`/`missing_fixes`，报告 HTML 增加“补丁完整性”区块。

### 5.5 测试策略

- `internal/patch`：规则解析（advisory/rename/prerequisite）、命令拼接（多包、多命令、rebuild 不自动）、循环依赖拒绝；
- `internal/server`：campaign fixture“A 依赖 B”——dry-run 应生成两条命令，任务 `cve_ids` 只含 A 的 CVE，`fix_set` 含 B；
- `internal/store`：`fix_set_hash` 去重、post-patch 按闭包验证的 DB 集成测试；
- 现有 `snapshot.json` 不动；新增 fixture 覆盖 Ubuntu/Alpine/Amazon 与依赖场景后再更新基线。

---

## 6. 发行版数据源接入评估

> 本小节只做评估与设计，不写代码。所有 URL 已在本轮做可达性检查。

### 6.1 Ubuntu（优先级：P1，成本中，收益大）

**现状**

- 匹配层已支持 `Ubuntu:22.04:LTS` 等 OSV ecosystem（`internal/cve/feed.go`、`internal/cve/loader.go:757-829`），但没有独立 ubuntu 源；
- 当前 Ubuntu 数据只能来自 OSV 按包查询（`RefreshAllOSV`），覆盖范围受当前资产包清单限制。

**候选源**

| 源 | 地址/格式 | 评估 |
|---|---|---|
| Canonical security-metadata OVAL | `https://security-metadata.canonical.com/oval/com.ubuntu.<release>.cve.oval.xml.bz2`（已验证 200） | 按 release 的 OVAL，含受影响包与 fixed 版本；适合全量快照；解析成本中 |
| Ubuntu Security Notices / CVE Tracker | GitHub `CanonicalLtd/ubuntu-cve-tracker`、security notices 仓库 | 公告级信息（USN → CVE → 包），适合补依赖规则与 SourceRef |
| OSV（继续保留） | `api.osv.dev` 的 `Ubuntu:*` ecosystem | 继续作为匹配补充，不作为唯一来源 |

**落地建议**

新增 `ubuntu` source：抓取目标 release 的 OVAL（按 agent OSVersion 选择），解析为 `cve_feed`；`sourceRank` 将 `ubuntu` 视为原生源（与 debian 同级）；OSV 保持兜底。同时把 USN 公告解析为“同公告多包”依赖规则的种子数据。

### 6.2 Alpine（优先级：P1，成本低，收益大）

**现状**

- 版本比较已支持 Alpine（`internal/cve/apkver.go`），匹配层有 `Alpine:v*` ecosystem 过滤；
- 没有独立 alpine 源。

**候选源**

| 源 | 地址/格式 | 评估 |
|---|---|---|
| Alpine secdb（官方） | `https://secdb.alpinelinux.org/v3.20/main.json`、`community.json`（已验证 200） | JSON：`packages[] { pkg.name, pkg.secfixes: { version: [CVE...] } }`；格式简单，按“版本 → 修复 CVE 列表”直接可匹配 |

**落地建议**

新增 `alpine` source：按 agent OSVersion 的 `major.minor`（如 `v3.20`）抓取 `main` + `community` 两个 JSON，入库 `cve_feed`；匹配时用已安装版本查 secfixes，并配合 `apkVersionCompare` 判断是否已修复。该源还天然适合生成“该 CVE 的修复版本”推荐。

### 6.3 Amazon Linux（优先级：P2，先验证再投入）

**现状**

- snapshot 已有 `linux-amazon-openssh` fixture，说明至少存在一条手工/OSV 路径；
- `cve_feed` 中没有 amazon 源。

**候选源**

| 源 | 地址/格式 | 评估 |
|---|---|---|
| Amazon Linux Security Center（ALAS） | `https://alas.aws.amazon.com/`（已验证 200） | 官方页面，但**未提供稳定、结构化的 JSON/XML API**；直接抓页面风险高 |
| OSV | `api.osv.dev` | 需先验证 OSV 数据集是否覆盖 Amazon Linux ecosystem（本轮未确认），若覆盖则成本最低 |
| 社区/Wazuh ALAS feed | 第三方 | 数据可用但有同步/许可/稳定性风险，建议仅作为临时对照 |

**落地建议**

先做一次小规模验证：查询 OSV 是否有 `amazonlinux`（或 ALAS）ecosystem 记录；若覆盖，优先接 OSV；若没有，再评估 ALAS 页面抓取（需要维护页面选择器，脆弱），或暂缓并用手工种子 + `custom_intel` 兜底。**在验证完成前，不要承诺 Amazon Linux 全量召回。**

### 6.4 接入后的必做配套

- `sourceOrder`/`sourceRank` 增加 `ubuntu`/`alpine`/`amazon`，并把原生源判定数据化；
- 新增源后跑 `TestAccuracySnapshot`，若去重优先级变化导致 snapshot 变化，需人工确认后更新基线；
- 为三个源各加一组 fixture（active/fixed、release 边界、包改名场景）。

---

## 7. 实施路线建议

### 第一步（低风险，先行）：可见性

- campaign 返回 `skipped` 明细（asset/KB/原因）；
- 推荐 API 与报告标记“不可自动部署 / 需手工下载”；
- 补充 `kb_downloads` 数据链路，让 KB 任务不再全部被静默跳过。

### 第二步（收益大）：数据源补强

1. Alpine secdb（成本低，先做）；
2. Canonical OVAL + USN 公告（成本中，收益最大）；
3. Amazon Linux 验证 OSV 覆盖后再决定。

### 第三步（结构性）：补丁闭包

- 依赖规则表 + `fix_set` 数据模型；
- 命令层多包/多命令；
- 去重键升级为 `fix_set_hash`；
- post-patch 验证按闭包判定并输出 `missing_fixes`；
- 报告增加补丁完整性区块。

### 第四步（回归保障）

- 每个改动点配套单元/集成测试；
- 扩展 accuracy snapshot 到 Ubuntu/Alpine/Amazon 与依赖场景；
- 用真实备份库做一轮全量复扫，核对 post-patch passed/failed 与人工预期一致。

---

## 8. 附录：证据代码位置

| 主题 | 位置 |
|---|---|
| 匹配源顺序/去重 | `internal/cve/feed.go:343`（`MatchAssets`）、`internal/cve/feed.go:360-441`（`sourceOrder`/`sourceRank`/`betterMatch`） |
| OSV 按包抓取 | `internal/cve/loader.go:78`、`internal/cve/osv.go:104` |
| Ubuntu/Alpine ecosystem | `internal/cve/loader.go:757-829`、`internal/cve/feed.go:1028-1065`、`internal/cve/apkver.go` |
| 推荐聚合 | `internal/store/cve.go:261`、`internal/store/cve.go:341`、`internal/store/cve.go:398` |
| campaign 生成/静默跳过 | `internal/server/campaign_service.go:81`（约 170-240 行） |
| 命令构建 | `internal/patch/template.go:45-126` |
| 任务去重 | `internal/store/campaign.go:339` |
| post-patch 闭环 | `internal/store/patch.go:200`、`internal/store/patch.go:326-413`、`internal/server/worker.go:667-730`、`internal/server/patch_grpc.go:240` |
| KB 链接/下载选择 | `internal/server/msrc_links.go:53-170` |
| 迁移 | `internal/store/migrations/004_cve_results.up.sql`、`009_patch_tasks.up.sql`、`047_kb_downloads.up.sql`、`048_post_patch_verify.up.sql` |
| 准确率基线 | `internal/cve/testdata/accuracy/snapshot.json`、`internal/cve/accuracy_snapshot_test.go` |
