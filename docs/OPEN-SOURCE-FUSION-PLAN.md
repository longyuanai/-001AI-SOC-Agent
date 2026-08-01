# 001 AI-SOC-Agent · 开源能力融合实施方案

> 状态：已确认，Phase F1–F5 已完成
> 基线：v0.6，247 passed（兄弟仓库齐全）
> 更新日期：2026-07-29

## 1. 目标与边界

本方案融合 Sigma、pySigma、Wazuh、ElastAlert2、OpenSearch Security
Analytics 和 AI_SOC 的优势，把 001 AI-SOC-Agent 建成轻量、可嵌入、
可解释的 SOC 检测与分析副驾驶。

项目保持以下定位：

- 负责多源日志归一化、确定性规则检测、事件关联、统一 Finding 和 AI 辅助分析。
- 不替代 SIEM，不承担长期日志存储、全量检索、资产管理或端点 Agent 管理。
- 所有跨产品数据通过 `Finding`、`ProductAdapter`、CLI envelope 和
  `IntegrationGateway` 流转。
- v0.1 §1-§6、v0.5 §7-§10、v0.6 §15 的冻结契约不改。
- 规则匹配由 `RuleEngine` 执行；LLM 只做下游解释，不参与基础命中判定。
- 默认本地处理敏感日志，不调用真实外部 API，不增加未经批准的生产依赖。

## 2. 参考项目与能力取舍

| 项目 | 核心特点 | 本项目吸收 | 本项目不照搬 |
|---|---|---|---|
| [Sigma](https://github.com/SigmaHQ/sigma) | YAML 检测规则、标准字段、MITRE 标签、跨 SIEM 表达 | 规则 ID、标题、描述、日志源、战术、技术、严重度和字段要求的统一元数据 | 不整库复制规则；引入规则前单独审查 Detection Rule License |
| [pySigma](https://github.com/SigmaHQ/pySigma) | Parser、Processing Pipeline、Backend 分离 | 归一化字段映射与规则执行解耦，为未来可选 Sigma loader 预留接口 | v0.6.1 不增加 pySigma 依赖，不把查询转换器当实时关联引擎 |
| [Wazuh](https://github.com/wazuh/wazuh) | Agent/Manager、Decoder、Ruleset 分层，支持文件和 syslog | 输入适配器、解析器、检测器分层；允许 Wazuh/ELK/Splunk 作为上游数据源 | 不嵌入 Wazuh Manager、端点 Agent 或完整规则运行时 |
| [ElastAlert2](https://github.com/jertel/elastalert2) | 时间窗、阈值、去重、静默期和告警路由 | 有界滑动窗口、分组键、告警指纹、抑制期、可注入时钟 | 不依赖 Elasticsearch/OpenSearch 轮询才能检测 |
| [OpenSearch Security Analytics](https://github.com/opensearch-project/security-analytics) | Detector → Finding → Alert 生命周期 | 分离规则命中、标准 Finding、兼容 Alert/Case 展示，并通过 Registry 查询和关联 | 不引入 JVM、OpenSearch 插件和存储侧执行依赖 |
| [AI_SOC](https://github.com/zhadyz/AI_SOC) | 本地 LLM、异步分析、RAG、反馈闭环和多阶段关联 | 确定性检测后的 narrative、处置建议、人工反馈和可选知识检索 | 不复制多微服务和重依赖组合，不让 LLM 自动执行响应动作 |

融合原则是“复用设计边界与成熟模式”，不是“引入所有运行时”。

## 3. 当前基线

### 3.1 已具备

- SSH、Windows Event XML、Nginx、Okta 四类日志解析。
- `NormalizedEvent` 统一事件对象和 UTC 时间归一化。
- 五个 MITRE ATT&CK 模式：
  - T1110 Brute Force
  - T1078 Geo Anomalous Login
  - T1548 Privilege Escalation
  - T1021 Lateral Movement
  - T1110.004 Credential Stuffing
- `SOCPattern`、`RuleRegistry`、`RuleEngine` 检测链路。
- 有界滑动窗口、每分组 Finding、抑制名单和确定性 Alert ID。
- `Finding.host` 增强及跨产品关联字段。
- `SOCProductAdapter`、CLI §15 envelope、FastAPI 和 IntegrationGateway 接口。
- LLM tier、multi-agent narrative 等 v0.5 能力。

### 3.2 主要缺口

- `extra.continent` 尚无可靠生产富化来源，geo anomaly 规则缺少真实输入。
- `extra.password_hash` 尚无隐私安全的生成策略，credential stuffing 的同凭据分支受限。
- 规则元数据尚未形成可导出、可审计的统一 manifest。
- Finding 使用自动 UUID，跨批次相同命中的稳定去重指纹仍需放进 metadata。
- 检测状态主要按单批次计算，跨批次窗口、静默期和重启恢复尚未统一。
- 告警仅内存保存，尚无可选的外部持久化接口。
- syslog 实时接入按既定计划延后至 v0.7。

## 4. 目标架构

```text
文件 / stdin / ELK-Splunk Webhook / Wazuh / v0.7 Syslog
                         │
                         ▼
                Input Adapter Layer
                         │
                         ▼
          Parser / Decoder → NormalizedEvent
                         │
                         ▼
        Field Mapping + Local Enrichment Pipeline
                         │
                         ▼
     ┌──────────────── Detection Orchestrator ────────────────┐
     │ Rule Manifest → RuleRegistry → RuleEngine              │
     │                         │                               │
     │              Bounded Window State                      │
     │                         │                               │
     │        Suppression / Dedup / Stable Fingerprint        │
     └─────────────────────────┬───────────────────────────────┘
                               ▼
                  Finding Builder (§9 frozen)
                               │
              ┌────────────────┼─────────────────┐
              ▼                ▼                 ▼
       CLI §15 envelope   ProductAdapter     FastAPI/API
              └────────────────┼─────────────────┘
                               ▼
                 IntegrationGateway Registry
                               │
                               ▼
       Optional LLM Narrative / Runbook / Human Feedback
```

## 5. 核心设计

### 5.1 输入、解析和字段映射

借鉴 Wazuh Decoder 和 pySigma Pipeline，把输入协议、文本解析和规范字段映射分开：

1. Input Adapter 只负责接收字节、文本或 webhook payload。
2. Parser 只负责把一种格式转换成 `NormalizedEvent`。
3. Field Mapping Pipeline 从 `NormalizedEvent.extra` 提取检测字段，不修改冻结 schema。
4. Enricher 只做本地、可审计的补充，不静默访问网络。

统一检测词汇表：

| 语义 | 当前字段 | 兼容映射 |
|---|---|---|
| 事件时间 | `ts` | `@timestamp`, `event.created` |
| 发起实体 | `actor` | `src_ip`, `source.ip`, `user.name` |
| 目标实体 | `target` | `destination.host`, `user.target` |
| 动作 | `action` | `event.action` |
| 结果 | `result` | `event.outcome` |
| 日志族 | `source` | `logsource`, `service.name` |
| 扩展字段 | `extra` | continent、host、event_id、password_hash 等 |

映射规则必须显式、确定性、可单测；未知字段保留在 `extra`，不丢原始证据。

### 5.2 Sigma 兼容规则清单

继续使用 Python `Rule` 作为唯一执行接口，同时为每个模式提供只读 manifest：

```yaml
id: 001.brute_force
title: Brute force burst
status: stable
log_sources: [sshd, evtx, nginx, okta]
tactic: TA0006
technique: T1110
severity: high
group_by: actor
window: 60s
required_fields: [ts, actor, result]
```

manifest 用于展示、审计、文档和未来导入导出，不取代 `Rule.evaluate()`。

未来若启用 pySigma：

- 作为可选 extra 安装，不进入默认依赖。
- 第一阶段只导入无状态、单事件规则。
- 聚合、时间窗和跨源关联仍由本项目 `RuleEngine` 与 Window State 执行。
- 每条外部规则必须经过字段映射、许可证、性能和误报测试后才能启用。

### 5.3 有界状态、去重与抑制

借鉴 ElastAlert2：

- 窗口按 `(rule_id, group_key)` 隔离。
- 每组事件数受 `MAX_WINDOW_EVENTS` 限制。
- 统一使用 UTC，并支持测试注入固定时钟。
- 乱序事件按事件时间排序；超出允许迟到范围的事件记录原因后忽略或旁路。
- Finding metadata 保存稳定 `fingerprint`：
  `rule_id + host/actor + window_start + evidence dimensions`。
- 自动 UUID 继续作为 Finding 实例 ID；fingerprint 负责跨扫描去重。
- suppression 分为 allowlist、规则静默期和重复 Finding 抑制，三者分别审计。

v0.6 仍可使用内存状态；持久化通过协议接口扩展，默认不绑定数据库。

### 5.4 Finding 生命周期

借鉴 OpenSearch Security Analytics，定义但不新增共享 schema：

```text
Rule match
  → Finding（冻结 §9 schema）
  → Registry correlation / dedup
  → Alert（兼容现有 API）
  → Case narrative（可选 AI 层）
```

字段规则：

- `Finding.source` 固定为 `FindingSource.SOC`。
- `Finding.host` 优先使用受影响主机；若规则以攻击源 IP 为关联实体，则使用规范化 IP。
- MITRE tactic、technique、rule ID、fingerprint、分组维度进入 `metadata`。
- 原始日志或安全裁剪后的证据进入 `evidence`。
- `confidence` 表示检测证据置信度，不表示 LLM 自信程度。
- §15 stdout 只输出 `{"findings": [...]}`；诊断信息写 stderr。

### 5.5 AI 分析层

借鉴 AI_SOC，但把 AI 放在确定性检测之后：

- `ANALYST`：解释证据、攻击阶段和误报可能。
- `EXPLOITER`：从攻击者视角说明可能的下一步，不执行攻击。
- `SYNTHESIZER`：生成背景、攻击、影响三段式 narrative。
- 可选 `REVIEWER`：检查结论是否被 evidence 支持。
- tier 由严重度、事件数量和任务类型选择。
- 所有测试使用 `stub_router`，不得调用真实模型或外部 API。
- LLM 超时、格式错误或不可用时，Finding 和基础 Alert 仍正常返回。
- 自动封禁、隔离、删除或外发必须经过显式人工批准，本项目默认只给建议。

### 5.6 集成与部署

- 单仓调用：`python -m ai_soc_agent scan --input '<json>' --json`。
- 进程内集成：`SOCProductAdapter.scan()`。
- 跨产品集成：IntegrationGateway + FindingRegistry。
- SIEM 集成：ELK、Splunk、Wazuh 通过 webhook 或文件投递规范事件。
- 长期存储由外部 SIEM/Registry backend 负责。
- v0.7 新增默认 1514 的异步 syslog receiver；不默认绑定特权端口 514。

## 6. 分阶段实施

### Phase F1 · 规则标准化与审计

目标：让当前五个模式可枚举、可解释、可审计。

- 新增 rule manifest 模型和五个内置 manifest。
- 校验 rule ID、MITRE 元数据、必需字段和 entry point 一致。
- 增加 manifest 列表/检查命令，但不改变现有 scan envelope。
- 为每条规则增加 real、normal、boundary、malformed-input 测试。

验收：不加生产依赖；冻结契约测试全绿；现有五个规则行为不回归。

### Phase F2 · 字段映射与安全富化

目标：让 geo anomaly 和 credential stuffing 获得可用且安全的输入。

- 建立 source-specific field mapping。
- GeoIP 只接受上游已提供 continent，或使用经批准的本地离线数据库。
- 凭据只接受不可逆、带域隔离的指纹；禁止保存明文密码。
- 缺失富化字段时规则降级并提供原因，不虚构数据。

验收：敏感字段测试、缺字段测试、跨日志源映射测试全部通过。

### Phase F3 · 跨批次状态与 Finding 去重

目标：支持慢速攻击、重复 webhook 和跨批次关联。

- 抽象 `WindowStateStore`，先实现有界内存版本。
- 增加稳定 fingerprint 和 suppression policy。
- 覆盖乱序、重复、窗口边界、内存上限和多租户隔离测试。
- 保留纯批处理路径，避免 CLI 一次性扫描产生隐式全局状态。

验收：结果可复现、内存有上限、重复 payload 不制造重复告警风暴。

### Phase F4 · AI narrative 与反馈闭环

目标：提高 SOC 工程师理解和处置速度。

- narrative 始终引用 Finding evidence。
- 输出建议处置步骤、验证步骤和不确定性。
- 记录人工标注：true positive、false positive、needs review。
- 反馈仅用于阈值评估和后续规则版本，不在线自动改规则。

验收：stub/mock 全覆盖；LLM 故障不影响检测；不得发起真实响应动作。

### Phase F5 · v0.7 实时接入

目标：在不引入 Kafka/Redis 的前提下提供最小实时路径。

- `asyncio.DatagramProtocol` 接收 syslog，默认端口 1514。
- 加入有界队列、背压、速率限制和解析失败隔离。
- 支持优雅关闭、健康检查和指标。
- Kafka、Redis Streams 仅在实际吞吐证明需要时再立项。

验收：UDP mock、突发流量、队列满、坏报文和关闭流程测试通过。

### Phase F6 · 可选 Sigma 生态接入

启动条件：内置规则清单、字段映射和状态层已稳定，并且有明确的外部规则需求。

- 先用少量公开规则做兼容性 PoC。
- 对比原生 Rule 与 Sigma 规则的准确率、耗时和维护成本。
- 只有收益明确时才批准 pySigma 可选依赖。
- 不兼容的聚合规则转换为经过评审的本地 Python Rule，而非静默降级。

## 7. 测试与质量门禁

每项实施至少覆盖：

- 正常攻击样本命中。
- 正常流量不命中。
- 阈值刚好命中和差一个不命中。
- 缺失、未知、畸形字段不抛未处理异常。
- 混合时区、乱序和重复事件。
- 多 actor/user/host 分组隔离。
- Finding host、source、severity、confidence、evidence、metadata 合规。
- CLI envelope 只有 `findings` 键。
- ProductAdapter 与 IntegrationGateway 契约。
- LLM 全部 mock，网络断开时测试仍可运行。

验证命令以仓库当前 `docs/tech-spec.md` §14.5 为准：

```powershell
poetry run pytest -q --tb=short
poetry run python -m ai_soc_agent scan --input '{"source":"sshd","events":[]}' --json
```

性能基线建议：

- 10,000 条规范事件的纯规则扫描建立可重复 benchmark。
- 窗口处理目标保持近似 O(n log n)，不得随规则数产生隐式全量笛卡尔积。
- 每组窗口严格执行事件上限。
- AI latency 单独计量，不计入确定性检测性能。

## 8. 安全、隐私与供应链

- 不保存或输出明文密码、token、cookie、Authorization header。
- 日志进入 LLM 前进行字段白名单和裁剪。
- evidence 默认最小化，报告不重复整批原始日志。
- 所有外部规则记录来源 URL、版本、许可证和内容哈希。
- 新依赖必须经过 issue 批准、许可证检查和漏洞扫描。
- 网络安全测试只使用仓库 fixture、授权环境、靶场或 CTF。
- 删除、隔离、封禁等响应动作不在本方案默认授权范围内。

## 9. 建议的 issue 顺序

| 顺序 | Issue | 结果 |
|---|---|---|
| 1 | RULE-MANIFEST-001 | 五个模式拥有统一、可校验的 Sigma-compatible manifest |
| 2 | FIELD-MAP-001 | 四类日志的检测字段映射统一 |
| 3 | ENRICH-001 | 安全的 continent 输入策略 |
| 4 | ENRICH-002 | 不可逆 credential fingerprint 策略 |
| 5 | STATE-001 | 有界跨批次 WindowStateStore |
| 6 | DEDUP-001 | Finding fingerprint、静默期与重复抑制 |
| 7 | FEEDBACK-001 | 人工反馈记录和离线评估 |
| 8 | SYSLOG-001 | v0.7 异步 syslog + 背压 |
| 9 | SIGMA-POC-001 | 可选 pySigma 兼容性与收益评估 |

一个 issue 一个 commit；每个 issue 先写失败测试，再做最小实现并跑全量回归。

## 10. 决策记录

1. **选择轻量原生 RuleEngine**：它已符合共享契约，五个状态规则无需新运行时。
2. **选择 Sigma-compatible，而非立即依赖 Sigma**：先获得标准化和可迁移性，避免依赖及规则许可证风险。
3. **选择外部 SIEM 集成，而非自建 SIEM**：长期存储、检索和 Agent 管理由成熟平台负责。
4. **选择 Finding 作为唯一跨产品语言**：不新增横向产品依赖。
5. **选择 AI 后置**：检测结果可测试、可解释，模型不可用时系统仍工作。
6. **选择分阶段引入实时能力**：先证明文件/webhook 链路，再在 v0.7 增加 syslog。

## 11. 开工确认点

建议先批准 Phase F1：

> 确认 OPEN-SOURCE-FUSION-PLAN，先实施 RULE-MANIFEST-001。

实施记录：

- 2026-07-29：完成 `RULE-MANIFEST-001`；五个 manifest、entry point
  审计、CLI list/validate 和 17 个新增测试落地。
- 2026-07-29：完成 `FIELD-MAP-001`；四源 canonical aliases、检测入口
  集成和 11 个新增测试落地。
- 2026-07-29：完成 `ENRICH-001`；采用上游 SIEM Geo metadata 路线，
  无网络/无数据库规范化和 12 个新增测试落地。
- 2026-07-29：完成 `ENRICH-002`；只接受 scoped HMAC 指纹，拒绝明文
  与旧式 hash，Finding evidence 脱敏，12 个新增测试落地。
- 2026-07-29：完成 `STATE-001`；Server 使用有界、去重、事件时间驱动的
  内存状态，CLI/Adapter 保持无状态，13 个新增测试落地。
- 2026-07-29：完成 `DEDUP-001`；稳定 Finding metadata fingerprint、
  有界 cooldown 策略和 Adapter 跨调用抑制，12 个新增测试落地。
- 2026-07-29：完成 `FEEDBACK-001`；有界人工标签存储、鉴权 API、
  过滤/汇总且不在线改规则，12 个新增测试落地。
- 2026-08-01：完成 `SYSLOG-001`；标准库 asyncio UDP 接收器、默认
  1514、有限队列、坏报文隔离、运行指标和优雅关闭落地。
