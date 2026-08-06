-- CVE 情报标注（专有威胁情报 v2）。
-- 标注数据只通过迁移/代码演进（零运维）；服务启动/风险重算时自动生效。
-- exploited 或威胁级别按“风险下限”影响评分（类似现有 KEV 语义），
-- 不改变 RiskScore 公式与既有 EPSS/KEV 行为。
CREATE TABLE IF NOT EXISTS cve_intel_annotations (
    id            BIGSERIAL PRIMARY KEY,
    cve_id        TEXT NOT NULL UNIQUE,
    threat_level  TEXT NOT NULL DEFAULT 'MEDIUM',
    exploited     BOOLEAN NOT NULL DEFAULT FALSE,
    notes         TEXT NOT NULL DEFAULT '',
    source_ref    TEXT NOT NULL DEFAULT 'builtin',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cve_intel_annotations_enabled
    ON cve_intel_annotations(enabled);

-- 内置标注样例：4 条真实 CVE，均为已利用 + CRITICAL（回归基线）。
-- 新增/修改标注 = 提交迁移；无后台 CRUD/热更新接口。
INSERT INTO cve_intel_annotations (cve_id, threat_level, exploited, notes) VALUES
(
    'CVE-2021-44228', 'CRITICAL', TRUE,
    'Log4Shell：Apache Log4j 2.x <= 2.14.1 JNDI 注入远程代码执行，已被大规模利用，勒索/挖矿团伙活跃使用；建议优先修复并排查相关资产。'
),
(
    'CVE-2017-0144', 'CRITICAL', TRUE,
    'EternalBlue：SMBv1 远程代码执行，WannaCry/NotPetya 等勒索蠕虫核心利用链；老旧 Windows 资产需优先处置。'
),
(
    'CVE-2023-34362', 'CRITICAL', TRUE,
    'MOVEit Transfer SQL 注入远程代码执行，Clop 勒索团伙 0-day 大规模利用；建议立即升级并排查受控文件传输资产。'
),
(
    'CVE-2024-3400', 'CRITICAL', TRUE,
    'Palo Alto PAN-OS GlobalProtect 网关命令注入，已被在野利用；防火墙类资产需优先升级。'
)
ON CONFLICT (cve_id) DO NOTHING;

ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS intel_threat_level TEXT NOT NULL DEFAULT '';
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS intel_exploited BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE cve_results ADD COLUMN IF NOT EXISTS intel_notes TEXT NOT NULL DEFAULT '';

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS intel_threat_level TEXT NOT NULL DEFAULT '';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS intel_exploited BOOLEAN NOT NULL DEFAULT FALSE;
