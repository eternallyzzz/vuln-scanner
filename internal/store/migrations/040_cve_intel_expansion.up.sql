-- CVE 情报标注与规则扩充（专有威胁情报 v3）。
-- 仅追加种子（ON CONFLICT DO NOTHING），无 schema 变更；
-- 标注在启动/风险重算生效，规则由 SyncCustomIntel 启动镜像进 cve_feed。
INSERT INTO cve_intel_annotations (cve_id, threat_level, exploited, notes) VALUES
(
    'CVE-2024-3094', 'CRITICAL', TRUE,
    'xz Utils 5.6.0/5.6.1 liblzma 供应链后门，可劫持 SSH 认证；建议立即降级/升级并排查受影响构建链。'
),
(
    'CVE-2023-44487', 'CRITICAL', TRUE,
    'HTTP/2 Rapid Reset 协议级拒绝服务，被大规模利用；建议升级服务器软件并启用 HTTP/2 流控/限速。'
),
(
    'CVE-2024-6387', 'CRITICAL', TRUE,
    'OpenSSH regreSSHion 信号处理器竞态远程代码执行（8.5p1-9.7p1/glibc）；建议优先升级并限制 SSH 暴露面。'
),
(
    'CVE-2023-4863', 'CRITICAL', TRUE,
    'libwebp 堆缓冲区溢出，经恶意图片触发已被在野利用；建议升级 WebP 处理库并扫描受影响应用。'
)
ON CONFLICT (cve_id) DO NOTHING;

-- 带 CPE 的自定义规则样例：有 cpe 时按 CPE 产品+版本匹配（严格），
-- 无 cpe 时回退名称匹配；min/max/fixed_in 版本范围语义与现有规则一致。
INSERT INTO custom_intel (intel_id, title, summary, severity, cvss_score, advisory_url, source_ref, affected) VALUES
(
    'CUSTOM-2026-005',
    'OpenSSL < 3.0.7',
    '内置 CPE 规则样例：OpenSSL 3.0.x < 3.0.7 存在 punycode 解码缓冲区溢出（CVE-2022-3602/3786），建议升级到 3.0.7 及以上。',
    'HIGH', 7.5,
    'https://www.openssl.org/news/vulnerabilities-3.0.html',
    'builtin',
    '[{"name":"openssl","cpe":"cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*","max_ver":"3.0.7","fixed_in":"3.0.7"}]'::jsonb
),
(
    'CUSTOM-2026-006',
    'curl < 7.87.0',
    '内置 CPE 规则样例：curl < 7.87.0 存在 HSTS 绕过与 HTTP 代理 RCE（CVE-2022-43551/43552），建议升级。',
    'HIGH', 7.5,
    'https://curl.se/docs/vulnerabilities.html',
    'builtin',
    '[{"name":"curl","cpe":"cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*","max_ver":"7.87.0","fixed_in":"7.87.0"}]'::jsonb
),
(
    'CUSTOM-2026-007',
    'HAProxy 2.4.x < 2.4.4',
    '内置 CPE 规则样例：HAProxy 2.4.x < 2.4.4 存在 Content-Length 整数溢出请求走私（CVE-2021-40346），建议升级到 2.4.4 及以上。',
    'HIGH', 7.5,
    'https://www.haproxy.org/',
    'builtin',
    '[{"name":"haproxy","cpe":"cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*","max_ver":"2.4.4","fixed_in":"2.4.4"}]'::jsonb
)
ON CONFLICT (intel_id) DO NOTHING;
