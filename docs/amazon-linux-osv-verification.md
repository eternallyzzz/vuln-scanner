# Amazon Linux OSV 覆盖验证记录

- 日期：2026-08-07
- 验证方式：调用 `POST https://api.osv.dev/v1/query`，查询包 `openssh` 在不同 ecosystem 下的记录数
- 目的：决定 Amazon Linux 数据源接入方案（本轮只验证，不写抓取代码）

## 结果

| ecosystem 名称 | HTTP 结果 | 说明 |
|---|---|---|
| `amazonlinux` | 400 Bad Request | OSV 不识别该 ecosystem，无法按此查询 |
| `Amazon` | 400 Bad Request | 同上，不识别 |
| `AlmaLinux` | 200，26 条 vulns | 对照组：OSV 对同族 RPM 发行版有覆盖 |
| `Ubuntu` | 200，89 条 vulns | 对照组：Ubuntu 覆盖正常（本项目的 Ubuntu 源路径有效） |

## 结论

OSV 官方数据集中**没有 Amazon Linux ecosystem**，无法用 OSV 作为 Amazon Linux 的稳定来源。ALAS 官网（`alas.aws.amazon.com`）目前没有稳定的结构化 JSON/XML API，页面抓取脆弱且需要持续维护。

因此本轮按计划**不实现 Amazon Linux 源**：

- 短期：继续依赖手工种子与 `custom_intel` 兜底（现有 `linux-amazon-openssh` accuracy fixture 保持有效）；
- 中期：若需要全量召回，再评估 ALAS 页面抓取或经过许可评估的社区 feed（Wazuh ALAS 等），并作为独立议题立项。
