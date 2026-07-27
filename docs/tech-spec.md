# 001 AI-SOC-Agent · 技术方案

> **本文是唯一技术方案来源**。`PHASE-2.md` 已并入 §14，不再单独维护。
> **写给谁看**: 派活给 Codex 前必读；§14 是实施入口，§15 是验收基线。
> **准确性约定**: 本文描述的是**已实现的现状**，不是意图。写"计划"的地方一律
> 放在 §16 路线图里，与现状分开。发现文档与代码不一致时，**以测试为准**并回来改本文。

## 1. 业务问题

企业 SOC 团队每天面对海量 SSH/Windows/Nginx/Okta 日志，靠人工或简单正则告警：

- **告警疲劳**: 每天几千条失败登录，人眼看不过来
- **漏报**: 慢速爆破（每天 3 次失败，持续一周）逃过静态阈值
- **响应慢**: 从告警到处置平均 4 小时
- **关联弱**: 同一账号在 SSH + VPN + Web 多点异常，人工拼不起来

## 2. 产品定位

**AI SOC 日志分析助手**，接收多源日志，输出分级告警 + 处置建议。

- 输入: SSH auth.log / Windows Event XML / Nginx access / Okta System Log JSON
- 输出: v0.5 `Finding`（给 IntegrationGateway）、`Alert`（给 `/alerts` API）、
  Markdown 事件报告（给人看）

**不是** SIEM 替代品，是 SOC 工程师的 AI 副驾驶。

## 3. 关键能力（MoSCoW · 现状）

| 优先级 | 能力 | 状态 |
|--------|------|------|
| Must | SSH auth.log 解析（任意 auth method） | ✅ |
| Must | Markdown 事件报告 | ✅ |
| Must | LLM 事件研判 | ✅ 单批次单次调用 |
| Should | Windows Event Log 解析（4624/4625/4648） | ✅ |
| Should | Nginx access log 解析（含 Web 登录识别） | ✅ |
| Should | Okta 登录日志 | ✅ |
| Should | 关联规则（5 条 MITRE 模式） | ✅ 见 §7 |
| Should | FastAPI server（接 ELK / Splunk） | ✅ `/ingest` `/alerts` `/health` |
| Should | IntegrationGateway ProductAdapter | ✅ `SOCProductAdapter` |
| Could | 自定义规则 DSL | ❌ 未开始 |
| Could | 实时流（Kafka / Redis Streams） | ❌ 未开始 |
| Won't | 长期存储 | 推到外部 SIEM |

## 4. 总体架构

**关键事实：本产品有两条互相独立的处理路径，它们目前不汇合。**
这是理解代码最重要的一点，早期版本的架构图把它画错了（画成 Analyzer → Correlator
串联），实际上规则路径完全不调 LLM，LLM 路径完全不看规则。

```
              sshd / evtx / nginx / okta  ── Parsers ──► NormalizedEvent[*]
                                                              │
                        ┌─────────────────────────────────────┴──────────────┐
                        ▼                                                    ▼
              ┌───────────────────┐                              ┌────────────────────┐
              │  路径 A · 确定性  │                              │  路径 B · LLM 研判 │
              │  RuleEngine       │  不调 LLM，可离线             │  analyzer.py       │
              │  patterns/*       │                              │  单批次单次调用     │
              └─────────┬─────────┘                              └─────────┬──────────┘
                        │ Finding[*]                                       │ AlertAssessment
          ┌─────────────┼─────────────┐                                    ▼
          ▼             ▼             ▼                          ┌────────────────────┐
   CLI `scan --json`  SOCProduct   correlate()                   │  reporter.py       │
   (Gateway envelope)  Adapter     └─► Alert[*] ─► /alerts       │  Markdown 报告     │
                       (v0.5)                                    └────────────────────┘
                                                                         ▲
                                                                 CLI `analyze -i FILE`
```

**入口一览**：

| 入口 | 路径 | 调 LLM | 阈值 profile |
|------|------|--------|--------------|
| `ai-soc scan` / `python -m ai_soc_agent scan` | A | 否 | `detection_facts()` |
| `SOCProductAdapter.scan()`（IntegrationGateway） | A | 否 | `detection_facts()` |
| `POST /ingest` → `correlate()` | A | 否 | `STREAMING_PROFILE` |
| `ai-soc analyze` | B | 是 | 不适用 |

> **已知产品缺口**：路径 B 的 LLM 完全没有参与路径 A 的告警分级。§14.1 里
> "SOCPattern 提供 LLM 评估 hook" 这句话从未实现。见 §16 `SOC-LLM-TRIAGE`。

## 5. 模块设计（与代码一致，签名以此为准）

### 5.1 `parsers.py`

```python
def parse_line(line, *, year=None, now=None) -> NormalizedEvent | None   # sshd
def parse_evtx_line(line) -> NormalizedEvent | None                      # Windows XML
def parse_nginx_line(line) -> NormalizedEvent | None                     # nginx combined
def parse_okta_record(record: dict) -> NormalizedEvent | None            # Okta System Log
def parse_file(path, *, log_type="sshd") -> list[NormalizedEvent]
def is_login_endpoint(request: str) -> bool                              # nginx 登录端点判定
```

要点：

- `parse_line` 的 `now` 用于**推断 syslog 缺失的年份**：晚于参考时刻 1 天以上的日期
  读作去年，否则跨年那一刻的爆破会被拆成相隔一年的两半。`year` 显式指定时不推断。
- sshd 匹配 `Failed <method>` / `Accepted <method>`，method 存入 `extra.auth_method`。
  **`Invalid user X from IP` 刻意不解析**（见 §13 风险）。
- nginx 只有 `POST`/`PUT`/`PATCH` 打到认证路径才记为 `action="web_login"`；
  `GET /login` 是加载表单，不是认证尝试。认证路径段可用
  `AI_SOC_LOGIN_PATH_SEGMENTS` 追加。

### 5.2 `normalizer.py`

```python
@dataclass(frozen=True)
class NormalizedEvent:
    ts: datetime        # 可能 naive，下游一律按 UTC 归一后再比较
    actor: str          # src IP / user / process
    action: str         # ssh_login / web_login / sudo_exec / windows_login ...
    target: str         # host / user / URL path
    result: str         # success | failure | unknown
    source: str         # sshd / nginx / okta / windows / vpn / linux-audit
    raw: str = ""
    extra: dict = {}
```

### 5.3 `config.py` —— 所有检测调参的唯一来源

阈值曾经散落在规则、`correlate()` 和 CLI 三处字面量里，同一份日志走不同入口
出不同结果。现在收敛成**两个具名 profile**：

| Profile | 使用方 | 差异 |
|---------|--------|------|
| `detection_facts()` | CLI `scan`、Gateway adapter | 爆破 5 次 / 60 秒 |
| `STREAMING_PROFILE` | `correlate()` → `/ingest` | 爆破 10 次 / 300 秒 |

流式入口面对的是持续水流，刻意用更钝的阈值。**其余调参走 payload，不要新增字面量。**

### 5.4 `patterns/` —— MITRE 规则库

`base.SOCPattern` 继承共享 `Rule`，子类只实现 `matched_event_groups()`，
基类负责 Finding 构造、证据收集、告警元数据。两个窗口原语：

- `count_windows(...)` —— 按分组计数（爆破、提权）
- `distinct_windows(...)` —— 按分组去重计数（跨大洲、跨主机、跨源族）

**两者都是"每个分组各返回一个窗口"**，所以一批日志里 3 个 IP 同时爆破会出 3 条
finding，而不是 1 条。

### 5.5 `correlator.py`

```python
def detect_patterns(events, *, facts=None, engine=None) -> list[Finding]
def finding_to_alert(finding) -> Alert
def correlate(events) -> list[Alert]      # 用 STREAMING_PROFILE
```

`finding_to_alert` **永不返回 None**：缺可选元数据时降级成不太精确的 Alert，
而不是让整条检测从 `/alerts` 消失。

### 5.6 `analyzer.py` / `prompts.py`

```python
def analyze_events(events, router, *, max_batch=20) -> AlertAssessment   # 单个，不是 list
```

Prompt 唯一副本在 `prompts/incident_triage/v1.yml`，由 `prompts.load_prompt()` 加载。
**不要在 Python 里再写一份**。LLM 返回畸形时抛 `AnalyzerError`，不裸抛 `JSONDecodeError`。

### 5.7 `reporter.py`

```python
def render_markdown(events, assessment, *, source_path="") -> str
```

### 5.8 `server.py`

`/ingest`（幂等、有界）、`/alerts`（可按 type 过滤）、`/health`（**不鉴权**，供探针）。

- 每次 ingest 只关联 `config.MAX_RULE_WINDOW_SECONDS` 窗口内的事件，成本不随运行时长增长
- 关联在锁外执行
- Alert id 由 `(type, actor)` 派生，重放同一批事件更新同一条告警而非堆积重复

### 5.9 `adapter.py`

`SOCProductAdapter` 暴露给 v0.5 IntegrationGateway。envelope 刻意省略 `source`，
由 adapter 注入冻结的 `FindingSource.SOC`（`"001"`）。

## 6. 配置项

| 环境变量 | 默认 | 作用 |
|----------|------|------|
| `AI_SOC_API_TOKEN` | 未设 | 设置后 `/ingest` `/alerts` 要求 `Authorization: Bearer <token>`；未设时启动打 warning |
| `AI_SOC_HOST` | `127.0.0.1` | 开发服务器绑定地址（容器内由 Dockerfile 显式传 `0.0.0.0`） |
| `AI_SOC_PORT` | `8080` | 开发服务器端口 |
| `AI_SOC_LOGIN_PATH_SEGMENTS` | 空 | 逗号分隔，追加自定义登录路由（如 `j_security_check`）。只增不减 |
| `LLM_PROVIDERS` | 由 `--provider` 设置 | 交给 `shared-llm-core` |

## 7. 检测规则清单

全部 severity = `HIGH`，全部通过 v0.5 `RuleEngine` 执行。

| Rule ID | Technique | Tactic | `alert_kind` | 触发条件 | 默认阈值 | conf |
|---------|-----------|--------|--------------|----------|----------|------|
| `001.mitre.t1110.brute-force-burst` | T1110 | TA0006 | `brute_force` | 同 IP 失败登录 | 5 次 / 60s | 0.92 |
| `001.mitre.t1110.004.credential-stuffing` | T1110.004 | TA0006 | `credential_stuffing` | 同凭据指纹打多账号；`cross_source` 模式下改为同账号跨 ssh+vpn+web 失败 | 3 账号 / 300s；跨源 3 族 / 600s | 0.91 |
| `001.mitre.t1078.geo-anomalous-login` | T1078 | TA0001 | `geo_anomaly` | 同 user 成功登录跨大洲（需 `extra.continent`） | 2 大洲 / 24h | 0.90 |
| `001.mitre.t1548.privilege-escalation` | T1548 | TA0004 | `privilege_escalation` | 同 user sudo 失败 | 3 次 / 120s | 0.87 |
| `001.mitre.t1021.lateral-movement` | T1021 | TA0008 | `lateral_movement` | 同 user 成功远程登录多主机 | 3 主机 / 600s | 0.88 |

**已知覆盖缺口**：

- `geo_anomaly` 依赖 `extra.continent`，但**没有任何解析器产出这个字段**，只有手工
  构造的事件能触发。要在真实数据上生效需要 GeoIP 富化（§16 `SOC-GEOIP`）。
- `credential_stuffing` 默认模式依赖 `extra.password_hash`，同样无解析器产出。
- nginx / okta 的失败**不带凭据指纹**，所以 Web 撞库只能靠跨源模式。

## 8. 数据与持久化

无落盘。`server.py` 持有进程内状态：事件环形缓冲（默认上限 10000，超出丢弃最旧）
+ 告警字典（**无上限、无老化**，见 §13 风险）。重启即清空，长期存储推外部 SIEM。

## 9. 安全与合规

- 日志含敏感信息（IP / user / 路径），本地处理，**不上云**
- LLM 调用走共享内核，审计全留痕
- `/ingest` `/alerts` 支持 bearer token 鉴权（§6）；`/health` 只报计数器，不含事件内容
- 容器以 `USER 65532:65532` 非 root 运行，镜像内不写入任何凭据

> ⚠️ **已知与承诺不符**：早期文档写"报告默认不含原始日志，只含归一化字段"，
> 但 `Finding.evidence` 装的**就是原始日志行**（`event_evidence()` 优先返回 `raw`）。
> 这是有意的取证需求，但与合规承诺冲突，需要一个脱敏开关。见 §16 `SOC-REDACT`。

## 10. 部署

```bash
# CLI（规则路径，不需要 LLM provider）
python -m ai_soc_agent scan --log-file samples/ssh_bruteforce.log
python -m ai_soc_agent scan --log-file samples/nginx_login_bruteforce.log --log-type nginx

# CLI（LLM 路径）
ai-soc analyze -i samples/ssh_bruteforce.log -o report.md

# API
export AI_SOC_API_TOKEN=$(python -c "import secrets;print(secrets.token_urlsafe(32))")
python -m ai_soc_agent.server

# 容器（构建上下文必须是 003AI+网络安全 共同父目录）
docker build -f 001AI-SOC-Agent/Dockerfile -t ai-soc-agent:0.1 .
docker run --rm -p 8080:8080 -e AI_SOC_API_TOKEN=... ai-soc-agent:0.1
```

## 11. 评估指标

| 指标 | 目标 | 当前可测性 |
|------|------|-----------|
| 解析准确率（已知格式） | ≥ 99% | ✅ 由 parser 单测覆盖 |
| 告警 precision | ≥ 85% | ❌ **无标注数据集，无法测量** |
| 告警 recall（对比人工） | ≥ 80% | ❌ **同上** |
| 单事件 LLM 耗时 | < 500ms | ❌ 无基准脚本 |

> precision / recall 目前是空头支票：没有标注语料、没有评测脚本，谁也无法验收。
> 要么补齐（§16 `SOC-EVAL`），要么在下一版把它们从"目标"降级为"愿景"。
> **不要在没有数据集的情况下让 Codex 去"提升 precision"——那是不可验收的任务。**

## 12. 接口契约

依赖 `shared-llm-core`（v0.1 LLM 契约 + v0.5 Finding/RuleEngine 契约，均已冻结）。

**本仓库消费的共享符号**（改动前必须回看真实导出）：

```
shared_llm_core            : ChatMessage ChatRequest ChatResponse ChatChoice ChatUsage LLMRouter
shared_llm_core.router     : TaskTier
shared_llm_core.finding    : Finding FindingSeverity FindingSource
shared_llm_core.rule_engine: Rule RuleContext RuleEngine RuleRegistry
shared_llm_core.gateway    : ProductAdapter
```

`SOCPattern.evaluate()` 返回 **`list[Finding]`**。早期文档写的 `RuleHit` 类型
**不存在**，不要照着写。

## 13. 风险

| 风险 | 现状 | 缓解 |
|------|------|------|
| **sibling 仓库 path 依赖** | `pyproject` 依赖 `../000shared-llm-core`，独立 clone 装不上也测不了 | CI 按 `SHARED_LLM_CORE_REPO` 变量检出；长期需 suite 层决定发包或 submodule |
| **告警字典无上限无老化** | `/ingest` 的 `store.alerts` 只增不减，长跑会无限增长 | §16 `SOC-ALERT-TTL` |
| **`Invalid user` 双计数** | sshd 对同一次尝试同时打 `Invalid user X` 和 `Failed password for invalid user X`，两条都收会把失败次数翻倍、等效把阈值砍半 | 刻意不解析该行；要用需先按 pid+port 做同次尝试去重 |
| **LLM 幻觉** | 严重度可能错 | severity 白名单兜底、confidence 钳位到 0–1、畸形返回抛 `AnalyzerError` |
| **entry point 无人加载** | `pyproject` 声明的 `longyuanai.soc_patterns` 本仓库不读，消费方在 suite 侧 | 已加一致性测试防漂移；需 suite 层确认消费方，否则应删除声明 |
| **日志格式碎片** | 只覆盖 4 种主流格式 | 解析器可插拔，按需扩展 |

## 14. Phase-2 实施记录（v0.6，已完成）

> 本节是**已完成工作的记录**，不是待办。新任务见 §16。

### 14.1 Hook A · MITRE ATT&CK 模式库 —— ✅ 已交付

`src/ai_soc_agent/patterns/` 下 5 条规则（清单见 §7），全部继承 `SOCPattern`，
全部通过 `RuleEngine` 执行，没有写死的 if-else。

**与原计划的偏差（重要）**：

- 原计划 `RuleEngine.load_patterns("ai_soc_agent.patterns")` —— **未采用**。实际是
  `RuleEngine(register_patterns())`，规则来自模块内 `PATTERN_TYPES` 元组。
- `pyproject.toml` 用的是 **`[tool.poetry.plugins."longyuanai.soc_patterns"]`**
  （Poetry 格式），不是原文写的 PEP 621 `[project.entry-points...]`。
- entry point 声明**本仓库不读取**，见 §13。
- `SOCPattern` 上的 "LLM 评估 hook" **未实现**，规则路径完全离线。

### 14.2 Hook B · 跨产品 correlation —— ✅ 已交付

`findings.correlation_host()` 把 IPv4 actor 塞进 `Finding.host`，非 IP 时回退到
`host` / `destination_host` / `computer`。约束照旧：不 import 兄弟产品代码、
不直接 HTTP 调其他产品、correlation 由共享 `RuleRegistry` 统一跑。

### 14.3 Hook C · 实时 syslog 接入 —— ❌ 未开始，延期到 v0.7

见 §16 `SOC-SYSLOG`。约束：不绑 <1024 端口（默认 1514）、不改 §15 envelope。

### 14.4 不要做的事（长期有效）

- ❌ 不改 `Finding` schema（共享契约，改了就破 v0.5 冻结）
- ❌ 不让 001 仓直接 import 002/003/etc（横向耦合）
- ❌ 不把规则写死在 `correlator.py` 的 if-else 里，必须走 `RuleEngine`
- ❌ 不打真外部 API（NVD / Okta），CI 不允许网络
- ❌ 不动 §15 契约测试
- ❌ 不在 `analyzer.py` 里重写一份 prompt —— 唯一副本在 yml
- ❌ 不新增阈值字面量 —— 一律进 `config.py`
- ❌ 不重新引入 `--basetemp` 覆盖（会让并发跑测试互相抢目录，Windows 上直接报错）

## 15. 验收基线（冻结契约）

**CLI envelope 的真实形状**：

```json
{"findings": [ { "id": "...", "severity": "...", "confidence": 0.92,
                 "title": "...", "description": "...", "host": "...",
                 "ts": "...", "evidence": [...], "tags": [...], "metadata": {...} } ]}
```

顶层**只有 `findings` 一个键**。`tests/test_adapter.py` 断言
`list(envelope) == ["findings"]`，`source` 键被刻意剔除由 adapter 注入。

> ⚠️ 历史文档曾写成 `{"findings": [...], "summary": {...}}`。**那是错的**，
> 照着加 `summary` 会让契约测试直接变红。

**冻结的契约测试**（改动它们等于改契约，需要单独决策）：

- `tests/test_adapter.py` —— Gateway envelope 形状
- `tests/test_cli_envelope.py` —— 跨仓 adapter 端到端
- `tests/test_rule_engine_contract.py` —— 所有 pattern 必须走 RuleEngine
- `tests/test_phase2_regression.py` —— Alert 投影不回归
- `tests/test_pattern_entry_points.py` —— pyproject 声明与 `PATTERN_TYPES` 不漂移

**验收命令**（跨平台，不要写死解释器绝对路径）：

```bash
poetry run pytest -q
poetry run ruff check src tests
echo '{"source":"sshd","events":[]}' | python -m ai_soc_agent scan --json   # => {"findings":[]}
```

当前基线：**178 passed + 4 skipped**（skip 的是需要 `000shared-integration` 的跨仓用例）。
新增任务必须在此基础上只增不减。

## 16. 路线图与待办

版本语义按**实际发布**对齐，不再沿用早期文档里对不上的编号。

| 阶段 | 内容 | 状态 |
|------|------|------|
| v0.1 | sshd 解析 + LLM 研判 + CLI | ✅ |
| v0.5 | 4 源解析 + Finding schema + RuleEngine + Gateway adapter + FastAPI + Docker | ✅ |
| v0.6 | MITRE 模式库（Hook A）+ 跨产品 host 富化（Hook B）+ 缺陷修复批次 | ✅ |
| v0.7 | 见下表 P0 | 🔜 |
| v1.0 | 实时流 + 多租户 + Web UI + SOAR 集成 | 计划 |

### 下一批候选任务（详细派活单见 `docs/TODO.md`）

| ID | 任务 | 价值 | 依赖 |
|----|------|------|------|
| `SOC-LLM-TRIAGE` | 让 LLM 对规则命中的 Finding 做二次研判，降误报 | **最高**——产品叫"AI 副驾驶"，但 AI 目前完全没参与告警分级 | 无 |
| `SOC-GEOIP` | 解析器富化 `extra.continent`，让 T1078 在真实数据上可用 | 高——规则已实现但无数据可喂 | 需离线 GeoIP 库 |
| `SOC-ALERT-TTL` | 告警老化 / 关闭 / 上限 | 高——长跑内存无限增长 | 无 |
| `SOC-EVAL` | 标注数据集 + precision/recall 评测脚本 | 高——否则 §11 指标不可验收 | 需人工标注 |
| `SOC-REDACT` | `evidence` 脱敏开关，兑现 §9 合规承诺 | 中 | 无 |
| `SOC-RULE-DSL` | YAML 自定义规则 | 中 | 无 |
| `SOC-SYSLOG` | syslog UDP 接收（Hook C） | 中 | 默认端口 1514 |
| `SOC-SSHD-DEDUP` | 同次认证尝试去重，解锁 `Invalid user` 行 | 低 | 无 |

---

**最近修订**: 2026-07-25 · 对齐实现现状：修正 envelope 契约（删除不存在的 `summary`）、
补 §4 双路径架构 / §6 配置项 / §7 规则清单 / §15 验收基线，`PHASE-2.md` 收敛为指针
**下次回看触发**: v0.7 启动 / 任一 §16 任务完工 / 共享契约变更
