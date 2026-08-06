-- 内置漏洞指纹规则（专有威胁情报 v1）。
-- 规则数据只通过迁移/代码演进（零运维）；服务启动时由 SyncCustomIntel
-- 镜像到 cve_feed（source='custom'）参与现有匹配/风险/告警链路。
CREATE TABLE IF NOT EXISTS custom_intel (
    id           BIGSERIAL PRIMARY KEY,
    intel_id     TEXT NOT NULL UNIQUE,
    title        TEXT NOT NULL,
    summary      TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'MEDIUM',
    cvss_score   DOUBLE PRECISION NOT NULL DEFAULT 0,
    advisory_url TEXT NOT NULL DEFAULT '',
    source_ref   TEXT NOT NULL DEFAULT 'builtin',
    affected     JSONB NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_custom_intel_enabled ON custom_intel(enabled);

-- 内置示例规则：真实公告 + CUSTOM-* 独立 ID（避免与公共 CVE 去重冲突）。
INSERT INTO custom_intel (intel_id, title, summary, severity, cvss_score, advisory_url, source_ref, affected) VALUES
(
    'CUSTOM-2026-001',
    'Nginx < 1.22.0',
    '内置规则示例：旧版 Nginx 缺少 1.22 安全修复，建议升级到 1.22.0 及以上。',
    'HIGH', 7.5,
    'https://nginx.org/en/security_advisories.html',
    'builtin',
    '[{"name":"nginx","max_ver":"1.22.0","fixed_in":"1.22.0"}]'::jsonb
),
(
    'CUSTOM-2026-002',
    'OpenSSH < 9.6p1（Terrapin）',
    '内置规则示例：OpenSSH 9.6 修复前缀截断攻击（CVE-2023-48795），建议升级。',
    'MEDIUM', 5.9,
    'https://www.openssh.com/txt/release-9.6',
    'builtin',
    '[{"name":"openssh","max_ver":"9.6p1","fixed_in":"9.6p1"}]'::jsonb
),
(
    'CUSTOM-2026-003',
    'Redis Lua 脚本堆溢出',
    '内置规则示例：Redis 6.2.x < 6.2.13 与 7.0.x < 7.0.15 存在 Lua 脚本堆溢出（CVE-2023-45145）。',
    'HIGH', 8.8,
    'https://github.com/redis/redis/security/advisories/GHSA-35m5-8cvj-8783',
    'builtin',
    '[{"name":"redis","max_ver":"6.2.13","fixed_in":"6.2.13"},{"name":"redis","min_ver":"7.0.0","max_ver":"7.0.15","fixed_in":"7.0.15"}]'::jsonb
),
(
    'CUSTOM-2026-004',
    'MySQL Server < 8.0.36 多个漏洞',
    '内置规则示例：MySQL Server 8.0.x < 8.0.36 包含多个安全补丁（含 CVE-2024-21047 等）。',
    'HIGH', 7.5,
    'https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-36.html',
    'builtin',
    '[{"name":"mysql","max_ver":"8.0.36","fixed_in":"8.0.36"}]'::jsonb
)
ON CONFLICT (intel_id) DO NOTHING;
