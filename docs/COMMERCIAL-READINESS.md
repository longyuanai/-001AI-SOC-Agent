# 001 AI-SOC-Agent · 商业化技术基线与实施路线

> 文档 ID：COMMERCIAL-BASELINE-001  
> 状态：approved for implementation  
> 基线日期：2026-08-01  
> 当前基线：v0.7，274 tests passing  
> 目标形态：可私有化部署的 SOC 检测与 AI 告警解释引擎

## 1. 产品边界

AI-SOC-Agent 的商业定位是接入现有 SIEM、日志平台和安全运营流程的检测副驾驶：

- 解析并归一化 SSH、Windows Event、Nginx、Okta 和 syslog 安全事件。
- 使用确定性规则完成时间窗检测、跨源关联、Finding 标准化和重复抑制。
- 使用 LLM 生成有证据引用的解释、攻击视角和处置建议。
- 通过 CLI、FastAPI、ProductAdapter 和 IntegrationGateway 对外提供能力。

本产品不承担以下职责：

- 不替代 SIEM 的长期原始日志存储、全文检索和资产管理。
- 不默认执行封禁、隔离、删号或其他不可逆响应动作。
- 不在没有人工审批时让 LLM 修改规则、阈值或生产配置。
- 不宣称具备任何认证；ISO 27001、SOC 2、等保等只作为控制映射目标。

商业化优先选择单客户私有化和托管单租户部署。多租户 SaaS 只有在身份、数据、
密钥、状态和审计实现强隔离后才能开放。

## 2. 当前能力与成熟度

| 领域 | 当前能力 | 当前等级 | 商用缺口 |
|---|---|---:|---|
| 日志输入 | 文件、JSON webhook、RFC 3164 SSH UDP | Beta | RFC 5424、TCP/TLS、可靠投递 |
| 解析归一化 | SSH/EVTX/Nginx/Okta、UTC、canonical fields | Beta | 厂商版本矩阵、兼容性回放 |
| 检测 | 5 个 MITRE 模式、窗口状态、跨批次关联 | Beta | 规则版本、调优、质量数据集 |
| Finding | host、evidence、fingerprint、dedup、Gateway | Beta | 交付路由、状态生命周期 |
| AI 分析 | tier 路由、多角色 narrative、失败降级 | Alpha | 真实模型评估、提示词版本、成本预算 |
| API | ingest/alerts/feedback/health | Alpha | OIDC/RBAC、限流、审计、幂等键 |
| 状态 | 有界内存窗口、可选 SQLite Alert | Alpha | 多副本一致性、迁移、备份演练 |
| 部署 | Docker、单进程 FastAPI | Alpha | 可重复发布、签名、回滚、HA |
| 运维 | 基础日志和 health | PoC | metrics、trace、告警、runbook、SLO |
| 质量 | 274 tests、mock LLM、冻结契约回归 | Beta | benchmark、soak、fuzz、安全扫描 |

当前允许的部署级别：开发、演示、授权靶场、单节点内部试点。当前禁止标记为
“企业级生产可用”或对外承诺 SLA。

## 3. 商业化目标架构

```text
日志源 / SIEM / Forwarder
          │
          ├── HTTPS webhook
          ├── Syslog TCP/TLS（商用主路径）
          └── Syslog UDP（best effort 兼容路径）
          │
          ▼
┌─────────────────────────────────────────────┐
│ Ingress Gateway                             │
│ TLS · OIDC/API client · rate limit · size   │
│ tenant context · request ID · audit         │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│ Normalize + Validate                        │
│ source parser · UTC · canonical mapping     │
│ schema version · redaction · quarantine     │
└──────────────────┬──────────────────────────┘
                   ▼
┌─────────────────────────────────────────────┐
│ Deterministic Detection                     │
│ RuleEngine · bounded state · dedup          │
│ rule version · evidence · Finding           │
└───────────────┬─────────────────┬───────────┘
                │                 │
                ▼                 ▼
      Durable alert/state     Optional AI analysis
      external DB/stream      evidence allowlist
                │                 │
                └────────┬────────┘
                         ▼
┌─────────────────────────────────────────────┐
│ Delivery                                    │
│ IntegrationGateway · webhook · SIEM export  │
│ retry/dead-letter · audit · metrics         │
└─────────────────────────────────────────────┘
```

架构原则：

1. 确定性检测与 LLM 分离；模型不可用不影响基础 Finding。
2. 入口先认证、限流、校验和脱敏，再进入状态与检测。
3. 每个有状态组件必须有容量、保留期、租户维度和清理机制。
4. 原始日志留在客户 SIEM；本产品只保留最小事件状态和规范告警。
5. 商用可靠路径不能依赖 UDP；UDP 只提供兼容和低成本接入。
6. 所有外部响应默认是可重试、可审计、可停用的下游动作。

## 4. 部署档位

### 4.1 Developer

- 单进程、内存状态、可选 SQLite。
- localhost 绑定，使用 fixture 或脱敏日志。
- 不提供 SLA，不处理客户生产数据。

### 4.2 Internal Pilot

- 单客户、单实例、HTTPS 反向代理、API client 鉴权。
- 外部 SIEM 保存原始日志，本地只保存有界 Alert。
- 每日备份、基础 metrics、运行手册和人工值守。
- 目标用于 30 天准确率、稳定性和运维验证。

### 4.3 Single-tenant Production

- 至少双实例入口，可靠消息或共享状态层。
- OIDC/API client、RBAC、审计、TLS、密钥托管。
- PostgreSQL 或经批准的外部状态服务，完成迁移和恢复演练。
- 监控、告警、容量计划、升级回滚和支持流程齐全。

### 4.4 Multi-tenant SaaS

- tenant_id 贯穿入口、状态、Finding、审计、指标和存储。
- 每租户密钥、配额、保留策略、导出目标和数据删除流程。
- 完成隔离测试、渗透测试、合规评审和事件响应演练后才可启用。

## 5. 服务等级目标

SLO 只在明确参考环境、数据规模和排除项后生效。首个商用参考环境定义为
4 vCPU、8 GiB RAM、本地 SSD、单客户、LLM 分析异步或关闭。

| 指标 | Internal Pilot | Production target |
|---|---:|---:|
| API 月可用性 | 99.5% | 99.9% |
| 100-event ingest p95 | ≤ 1 s | ≤ 500 ms |
| Finding 生成 p95 | ≤ 2 s | ≤ 1 s |
| 单节点规则吞吐 | ≥ 1,000 events/s | 由容量测试确认 |
| API 5xx | < 1% | < 0.1% |
| 有效输入解析失败率 | < 1% | < 0.1%（支持矩阵内） |
| 状态容量越界 | 0 | 0 |
| Alert RPO | ≤ 5 min | ≤ 1 min |
| 服务 RTO | ≤ 60 min | ≤ 30 min |

排除项：外部 LLM、上游 SIEM、网络、身份提供方不可用时间分别计量，不得吞并到
本服务指标。UDP 丢包不纳入可靠性承诺；生产 SLA 只覆盖已确认接收的事件。

## 6. 检测质量门禁

上线前必须建立带版本的 golden dataset，至少包含：

- 每个支持日志源的正常、攻击、边界、畸形和未知字段样本。
- 混合时区、乱序、重复、跨批次、跨 actor/user/host 样本。
- 每个 MITRE 规则的 true positive、false positive 和不确定样本。
- 已脱敏的客户代表性回放数据；使用前完成书面授权和保留期约定。

Internal Pilot 门禁：

- 支持格式解析准确率 ≥ 99%。
- 核心五规则 precision ≥ 85%，recall ≥ 80%。
- 高危规则不得仅因缺失富化字段而产生肯定性结论。
- 任何阈值修改必须关联数据集结果、评审人和规则版本。

Production 门禁：

- 客户数据回放达到双方确认的 precision/recall。
- 连续 7 天 soak test 无未解释内存增长、死锁和状态越界。
- 10 倍正常峰值 burst test 不崩溃；过载时有明确拒绝、丢弃或排队指标。
- 规则升级支持灰度、对比、回滚，不直接覆盖唯一生产版本。

## 7. 身份、授权与租户隔离

当前单一 bearer token 只允许内部试点。商用实现要求：

- 人员身份使用 OIDC/OAuth 2.0；机器接入使用独立 API client 或 mTLS。
- 最少角色：viewer、analyst、rule_admin、platform_admin、service_ingest。
- `/ingest`、`/alerts`、`/feedback`、规则管理和运维操作分别授权。
- token 不写入日志、Finding、错误响应或数据库；密钥来自 Secret Manager。
- 所有写操作记录 actor、tenant、request_id、action、result、timestamp。
- 拒绝默认管理员；生产启动时无身份配置必须 fail closed。
- 多租户模式下禁止使用进程全局无 namespace 的状态和缓存。

## 8. 数据安全与隐私

### 8.1 数据分类

| 数据 | 分类 | 默认保留 |
|---|---|---:|
| 原始安全日志 | 敏感 | 不持久化 |
| 规范事件窗口 | 敏感 | ≤ 24 h，有界内存/外部状态 |
| Finding/Alert | 机密 | 客户策略，默认 30 天 |
| analyst feedback | 机密 | 默认 90 天 |
| 审计记录 | 机密 | 默认 180 天或客户策略 |
| metrics | 内部 | 不含 user/IP/raw evidence 标签 |

### 8.2 控制要求

- 传输使用 TLS；生产禁止明文跨主机 webhook 和 syslog。
- 存储加密依赖受支持数据库或磁盘加密，并记录密钥轮换责任。
- evidence 使用字段白名单和长度限制，禁止密码、token、cookie、Authorization。
- LLM 输入只包含完成任务所需的最小字段，默认不发送 raw。
- 提供按租户导出、删除、保留期调整和 legal hold 的运维流程。
- 日志与错误不得打印完整 payload；调试模式在生产禁止启用。
- 备份与导出按原数据等级保护，恢复后必须执行访问控制验证。

## 9. 威胁模型

需要保护的资产：客户日志、身份凭据、Finding、规则、模型提示、API、持久状态和
供应链制品。

主要信任边界：

1. 日志源到 ingress。
2. ingress 到解析/检测进程。
3. 检测进程到状态数据库。
4. 检测进程到 LLM provider。
5. Finding delivery 到 IntegrationGateway/SIEM。
6. CI 到镜像仓库和生产部署。

最低威胁场景与控制：

| 威胁 | 必须控制 |
|---|---|
| 伪造日志制造误报 | 客户端身份、来源 allowlist、签名/受控网络、审计 |
| 超大/突发输入 DoS | body/datagram 限制、队列容量、限流、超时、指标 |
| 日志注入和终端转义 | 结构化输出、转义、禁止 raw 拼接到命令/HTML |
| 跨租户状态污染 | tenant namespace、授权校验、隔离测试 |
| Prompt injection | 字段白名单、模型后置、输出 schema、无自动响应权限 |
| 凭据/PII 泄漏 | redaction、最小 evidence、secret scanning、访问审计 |
| 规则供应链污染 | 来源/许可证/hash、代码评审、签名版本、回滚 |
| SQLite/DB 损坏 | 事务、备份、恢复演练、坏记录隔离 |
| 依赖或镜像被篡改 | 锁定、SBOM、漏洞扫描、制品签名、provenance |

每次新增协议、身份方式、外部 provider 或主动响应能力时更新 threat model。

## 10. 可观测性

商用版本必须提供：

- JSON structured logs：timestamp、level、service、version、request_id、tenant_id、event。
- metrics：接收、接受、拒绝、解析失败、队列深度、丢弃、规则命中、抑制、延迟、
  LLM 调用/失败/成本、DB 错误、delivery retry/dead-letter。
- readiness 与 liveness 分离；依赖不可用时 readiness 失败但保留诊断。
- trace 覆盖 ingest → normalize → detect → persist → deliver，禁止记录敏感 payload。
- 告警至少覆盖：错误率、队列持续高水位、持续丢弃、数据库失败、无事件、磁盘空间、
  证书到期、备份失败和规则命中异常变化。

禁止把 IP、用户名、Finding ID 等高基数字段直接作为 metrics label。

## 11. 可靠性、备份与灾备

- SQLite 只支持 Developer/Internal Pilot 单实例，不作为多副本共享数据库。
- Production 状态后端必须有事务、迁移、备份、连接池、超时和健康检查。
- schema migration 必须可前滚和回滚；升级前自动备份，禁止启动时静默破坏性迁移。
- 每月至少一次恢复演练，记录 RPO/RTO 实测值。
- webhook/delivery 使用幂等键、指数退避、最大重试和 dead-letter。
- 进程退出先停止接收，再排空有界队列，最后关闭状态和下游连接。
- 配置、规则、提示词和 schema 均有版本；Finding 记录产生它的规则版本。

## 12. 安全开发与供应链门禁

每次合并到 `main` 至少执行：

1. 单元、契约、集成和冻结 envelope 测试。
2. lint、格式、类型检查。
3. secret scan、依赖漏洞扫描、SAST。
4. Dockerfile/container scan；生产镜像不得以 root 运行。
5. 生成 SPDX 或 CycloneDX SBOM。
6. 新依赖许可证和维护状态评审。
7. 高风险改动的 threat-model delta。

发布制品要求：

- 版本使用 SemVer，镜像禁止只发布 `latest`。
- 锁定基础镜像 digest，生成 provenance，并对镜像/包签名。
- 发布说明包含迁移、配置变化、已知问题、回滚步骤和安全影响。
- 生产 secrets 不进入 Git、镜像、测试输出和构建缓存。

## 13. 测试矩阵

| 层级 | 必须覆盖 |
|---|---|
| Unit | parser、rule、state、dedup、persistence、auth、redaction |
| Contract | v0.1 §1-§6、v0.5 §7-§10、v0.6 §15 envelope |
| Integration | Gateway、真实子进程、DB、身份提供方 mock、delivery mock |
| Protocol | RFC 3164/5424、TCP/TLS、坏帧、半包、超时、重连 |
| Security | 越权、跨租户、注入、敏感输出、限流、DoS 边界 |
| Performance | steady、burst、长窗口、规则扩展、最大 evidence |
| Reliability | restart、queue full、DB down、LLM down、下游 down、恢复 |
| Upgrade | schema migration、前后版本兼容、回滚 |

测试不得调用真实外部 API，不得包含客户原始数据或真实 secret。

## 14. 商业化实施 backlog

### Gate C1 · Internal Pilot

| 顺序 | Issue | 交付 | Definition of Done |
|---:|---|---|---|
| 1 | COMM-DOC-001 | 本文档和商用路线冻结 | 文档评审、issue 顺序和边界明确 |
| 2 | SEC-AUTH-001 | API client auth + RBAC 基线 | fail closed、权限矩阵、≥15 tests |
| 3 | OBS-001 | structured logs + metrics | 无敏感 label、health/readiness、≥12 tests |
| 4 | EVAL-001 | golden dataset + 质量评估器 | 每规则 precision/recall 报告可复现 |
| 5 | PERF-001 | benchmark + burst/soak | 参考环境达 SLO，无无界增长 |
| 6 | OPS-001 | 部署/备份/恢复/回滚 runbook | 从空机部署和恢复演练通过 |
| 7 | SUPPLY-001 | CI 商用质量门禁 | tests/lint/type/security/SBOM/image scan |

### Gate C2 · Single-tenant Production

| 顺序 | Issue | 交付 | Definition of Done |
|---:|---|---|---|
| 8 | INGEST-002 | RFC 5424 + syslog TCP/TLS | 证书校验、帧边界、背压、协议测试 |
| 9 | DATA-002 | 外部 durable alert/state | migration、备份恢复、容量和超时测试 |
| 10 | DELIVERY-001 | 可靠 Finding webhook | idempotency、retry、dead-letter、审计 |
| 11 | RULE-OPS-001 | 规则版本/灰度/回滚 | 版本写入 Finding、对比评估、审批 |
| 12 | SEC-HARDEN-001 | threat model + 安全测试 | 高风险问题关闭、独立复核 |
| 13 | RELEASE-001 | 签名制品和升级机制 | SemVer、SBOM、provenance、rollback |

### Gate C3 · Multi-tenant Commercial Service

| 顺序 | Issue | 交付 | Definition of Done |
|---:|---|---|---|
| 14 | TENANT-001 | 端到端 tenant isolation | 状态/DB/cache/audit 隔离测试 |
| 15 | IDP-001 | OIDC/SSO 与客户角色映射 | token 生命周期、JWK rotation、审计 |
| 16 | HA-001 | 多副本与故障转移 | 无单点、演练满足 RPO/RTO |
| 17 | GOVERNANCE-001 | 保留/导出/删除/审计 | 客户策略可配置且验证 |
| 18 | SUPPORT-001 | SLA、监控、事件响应 | 值班、升级、客户通知和复盘模板 |

`SIGMA-POC-001` 不在 C1 关键路径。只有 golden dataset、字段映射和规则运维成熟，
且客户有外部 Sigma 规则需求时，才评审 pySigma 依赖、规则许可证和维护成本。

## 15. 上线门禁

### Internal Pilot Go/No-Go

- [ ] SEC-AUTH-001、OBS-001、EVAL-001、PERF-001、OPS-001、SUPPLY-001 完成。
- [ ] 真实 shared-core 和 contract stub 两种模式全绿。
- [ ] 冻结 CLI envelope 和 Gateway e2e 全绿。
- [ ] 30 天试点数据范围、授权、保留和删除责任已签字确认。
- [ ] 有明确 owner、监控、备份、回滚和事件响应联系人。

### Production Go/No-Go

- [ ] Gate C2 全部完成，所有关键风险有 owner 和截止日期。
- [ ] 7 天 soak、峰值 burst、DB/LLM/下游故障演练通过。
- [ ] 恢复演练满足 RPO/RTO，升级和回滚在预生产验证。
- [ ] 独立安全复核无未接受的 critical/high 问题。
- [ ] 客户验收 precision/recall、SLO、支持边界和数据责任。

### Multi-tenant Go/No-Go

- [ ] Gate C3 全部完成。
- [ ] 跨租户读写、缓存、队列、日志和指标隔离测试通过。
- [ ] 隐私、合规、事件响应和客户通知流程经责任人批准。
- [ ] 完成容量、故障域和成本模型评审。

## 16. 风险登记

| 风险 | 影响 | 当前措施 | 商用前措施 |
|---|---|---|---|
| UDP 丢包 | 漏检 | 计数、有限队列 | TCP/TLS 主路径、上游缓冲 |
| 规则误报 | 告警疲劳 | feedback、suppression | golden dataset、版本/灰度 |
| LLM 幻觉 | 错误解释 | AI 后置、schema | evidence citation、质量/成本门禁 |
| 单实例状态 | 重启/故障丢状态 | bounded memory、SQLite Alert | 外部 durable state、HA |
| 单 token | 越权 | 可选 bearer token | client identity、RBAC、audit |
| 供应链 | 制品被污染 | 依赖固定版本 | scan、SBOM、签名、provenance |
| 规则许可证 | 商业分发风险 | 内置自研规则 | 来源、许可证、hash、法务评审 |
| 客户数据 | 泄漏/合规 | 本地处理、最小 evidence | tenant、retention、deletion、DLP |

## 17. 决策与变更规则

- 冻结的 shared-core 和 CLI 契约只能 additive，不得因商业化破坏现有客户端。
- 新生产依赖必须有 issue、许可证、安全、运维和退出方案评审。
- 每个 issue 一个 commit；测试、文档和回滚说明随实现一起提交。
- 任何降低安全默认值、扩大网络暴露或增加数据保留的变更必须显式审批。
- 未达到对应 Go/No-Go gate 时，文档和销售材料不得使用更高部署等级描述。

下一实施项：`SEC-AUTH-001`。在其开工前先冻结权限矩阵、身份来源和部署档位；
不默认选择具体 OIDC/数据库/metrics 依赖，依赖在各 issue 设计评审中批准。
