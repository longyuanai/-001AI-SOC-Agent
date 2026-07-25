# 001 AI-SOC-Agent · 技术方案

## 1. 业务问题

企业 SOC 团队每天面对海量 SSH/Windows/Nginx/Okta 日志，靠人工或简单正则告警：

- **告警疲劳**: 每天几千条失败登录,人眼看不过来
- **漏报**: 慢速爆破（每天 3 次失败,持续一周）逃过静态阈值
- **响应慢**: 从告警到处置平均 4 小时
- **关联弱**: 同一 IP 在 SSH + VPN + Web 多点异常,人工拼不起来

需要一个 **AI 助手**自动:
- 解析多源日志 → 归一化事件
- 单事件严重度评分（CHEAP LLM）
- 跨事件关联（同 IP 5 分钟 10 次失败 → 告警）
- 输出可执行的告警

## 2. 产品定位

**AI SOC 日志分析助手**,接收多源日志,输出分级告警 + 处置建议。

- 输入: SSH auth.log / Windows Event XML / Nginx access / Okta JSON
- 输出: Markdown 告警报告 + 严重度等级 + 攻击链还原

**不是** SIEM 替代品,是 SOC 工程师的 AI 副驾驶。

## 3. 关键能力（MoSCoW）

| 优先级 | 能力 | 说明 |
|--------|------|------|
| Must | SSH auth.log 解析 | OpenSSH deb/rhel 格式 |
| Must | 单事件严重度评分 | 单 LLM 调用 CHEAP tier |
| Must | Markdown 告警报告 | CLI 输出 |
| Should | Windows Event Log 解析 | XML 格式,4625/4624/4648 |
| Should | Nginx access log 解析 | 标准 combined 格式 |
| Should | 关联规则 | 同 IP 时间窗内多次失败 → 告警 |
| Should | Okta 登录日志 | System Log API JSON |
| Should | FastAPI server | 接 ELK / Splunk webhook |
| Could | 自定义规则 DSL | YAML 规则文件 |
| Could | 实时流 | Kafka / Redis Streams |
| Won't | 长期存储 | 推到外部 SIEM |

## 4. 总体架构

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ SSH auth.log │    │ Windows XML  │    │ Nginx access │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           ▼
                  ┌──────────────────┐
                  │   Normalizer     │
                  │  Parsers per     │
                  │  log type        │
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐
                  │  Event Stream    │
                  │  NormalizedEvent │
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐
                  │   Analyzer       │ ◀── shared_llm_core (CHEAP)
                  │  per-event       │
                  │  severity        │
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐
                  │  Correlator      │
                  │  cross-event     │
                  │  rules           │
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐
                  │   Reporter       │
                  │  Markdown report │
                  └──────────────────┘
```

## 5. 模块设计

### 5.1 Parsers (`parsers.py`)

```python
def parse_line(line: str) -> NormalizedEvent | None: ...   # SSH
def parse_file(path: str) -> list[NormalizedEvent]: ...   # SSH 整文件
def parse_evtx_line(line: str) -> NormalizedEvent | None: ...  # Windows
def parse_nginx_line(line: str) -> NormalizedEvent | None: ...
def parse_okta_record(d: dict) -> NormalizedEvent | None: ...
```

返回 `NormalizedEvent`:
```python
@dataclass
class NormalizedEvent:
    ts: datetime
    actor: str          # src IP / user / process
    action: str         # login / exec / file_read
    target: str         # host / user / file
    result: str         # success / failure / unknown
    source: str         # sshd / auth / nginx / okta / windows
    raw: str
    extra: dict
```

### 5.2 Analyzer (`analyzer.py`)

```python
def analyze(events: list[NormalizedEvent]) -> list[AlertAssessment]:
    """对每个事件调用 CHEAP tier LLM, 评分 1-10"""
```

LLM 通过 `shared_llm_core.LLMRouter` 调,JSON mode 输出。

### 5.3 Correlator (`correlator.py`,Stage 2)

```python
def correlate(events: list[NormalizedEvent]) -> list[Alert]:
    """同 IP 5 分钟 10 次失败 → brute force"""
    """同 user 跨 SSH+VPN+Web → credential stuffing"""
```

### 5.4 Reporter (`reporter.py`)

```python
def render_markdown(alerts, events) -> str: ...
```

CLI 命令 `ai-soc analyze -i FILE -o REPORT.md`。

## 6. 数据与模型

无持久化。所有处理在内存,推外部 SIEM 长期存储。

## 7. 安全与合规

- 日志可能含敏感信息(IP/user/路径),本地处理,**不上云**
- LLM 调用走共享内核,审计全留痕
- 报告默认不含原始日志,只含归一化字段

## 8. 部署

- CLI: `ai-soc analyze -i ssh.log -o report.md`
- Server (Stage 2): Docker + FastAPI :8080
- 接 ELK: webhook `POST /ingest`

## 9. 评估指标

| 指标 | 目标 |
|------|------|
| 解析准确率 | ≥ 99% (已知格式) |
| 告警 precision | ≥ 85% |
| 告警 recall | ≥ 80% (对比人工) |
| 单事件 LLM 耗时 | < 500ms (CHEAP tier) |

## 10. 路线图

| 阶段 | 内容 |
|------|------|
| **PoC (当前)** | SSH 解析 + 严重度评分 + CLI, 15/15 测试 |
| **v0.1** | + Windows / Nginx / Okta 解析 + 关联规则 + FastAPI |
| **v0.5** | + 自定义规则 DSL + Kafka 接入 |
| **v1.0** | + 实时流 + 多租户 + Web UI |

## 11. 接口契约

依赖 `shared-llm-core` v0.1(冻结)。所有 LLM 调用通过 `LLMRouter`。

## 12. 风险

- **LLM 幻觉**: 严重度评分可能错 → 设置信度阈值 + 默认 conservative
- **日志格式碎片**: 每家厂商格式不同 → 先覆盖主流 4 种,后续扩展
- **性能**: CHEAP LLM 仍可能慢 → 批量 + 异步

## 13. 关键文件

- `src/ai_soc_agent/parsers.py` — 多日志源解析器
- `src/ai_soc_agent/analyzer.py` — LLM 评分
- `src/ai_soc_agent/cli.py` — CLI 入口
- `samples/` — 4 种日志 demo 文件
- `docs/TODO.md` — v0.1 issue 清单

## 14. Phase-2 实施(v0.6+ 改造指令)

> **本文是 Codex 实施 Phase-2 的入口**。§3 路线图 v0.6 之后所有改动以此为准。

### 14.1 Hook A · MITRE ATT&CK 攻击模式库(v0.6)

**目标**:覆盖 MITRE ATT&CK 主流 SOC 场景,从"基于阈值"升级到"基于战术模式"。

**新增文件**:

```
src/ai_soc_agent/patterns/
├── __init__.py
├── base.py              # SOCPattern 抽象基类,继承 v0.5 §8 Rule
├── brute_force.py       # T1110 BruteForceBurstRule:≥5 失败/60s 同 IP
├── geo_anomaly.py       # T1078 GeoAnomalousLoginRule:同 user 跨大洲登录
├── priv_esc.py          # T1548 PrivilegeEscalationRule:sudo 失败突变
├── lateral_movement.py  # T1021 LateralMovementRule:同 user 跨多 host 登录
└── credential_stuffing.py # T1110.004 CredentialStuffingRule:同密码多 user
```

**Schema**(每个 pattern 类必须实现):

```python
from shared_llm_core.rule_engine import Rule, RuleContext, RuleHit

class SOCPattern(Rule):
    """SOC-specific Rule,提供 LLM 评估 hook"""
    tactic: str  # MITRE ATT&CK tactic ID
    technique: str  # MITRE technique ID
    severity_default: FindingSeverity

    def match(self, ctx: RuleContext) -> bool: ...
    def evaluate(self, ctx: RuleContext) -> RuleHit: ...  # 可调 CHEAP LLM
```

**集成方式**:

- `src/ai_soc_agent/correlator.py` 改用 `RuleEngine.load_patterns("ai_soc_agent.patterns")`,**不再写死规则**
- 每个 pattern 通过 entry_points 注册(`pyproject.toml` 的 `[project.entry-points."longyuanai.soc_patterns"]`)
- LLM 调用走 `shared_llm_core.LLMRouter`,**不**直连 OpenAI

**测试要求**(每模式 ≥ 3 个 test function):

- `test_<pattern>_matches_real_attack_log`:从 `samples/mitre/<technique>.log` 加载真实日志,断言命中
- `test_<pattern>_ignores_normal_traffic`:从 `samples/mitre/normal.log` 加载,断言**不**命中
- `test_<pattern>_threshold_boundary`:刚好临界值命中 / 差一个不命中

**回归保证**:

- `tests/test_phase2_regression.py` —— 跑 v0.5 已知测试集,确保没回归
- `tests/test_cli_envelope.py` —— CLI envelope 形状不变(§15 契约)
- `tests/test_rule_engine_contract.py` —— 所有 pattern 必须从 v0.5 §8 RuleEngine 走,**不**写死 if-else

**commit 计划**(3 commit):

1. `feat(patterns): add SOCPattern base + entry_points` —— 框架就位,无新模式
2. `feat(patterns): add brute_force + geo_anomaly + priv_esc` —— 前 3 个模式
3. `feat(patterns): add lateral_movement + credential_stuffing + tests` —— 后 2 个模式 + 全套测试

### 14.2 Hook B · 跨产品 correlation(v0.6+)

**目标**:同一 IP 出 brute force + 已知 CVE,触发 `shared-llm-core` 跨仓 correlation。

**本仓改动**(001 只产 finding,不写 correlation):

- `src/ai_soc_agent/parsers.py` —— `NormalizedEvent.actor` 字段对 IP 类型**强制**塞进 `Finding.host`
- `tests/test_finding_host_field.py` —— 验证 host 字段在 brute force / geo anomaly 等模式产出时非空
- `src/ai_soc_agent/findings.py` —— `Finding` 构造时**显式**走 `host=event.actor if isinstance(event.actor, IPv4Address) else None`

**约束**:

- **不**直接 import 002 仓代码
- **不**写 `requests.post(...)` 调其他产品
- correlation 由 `000shared-llm-core` 的 `RuleRegistry` 统一跑(注册一条 `SameHostMultiSourceRule`)

**commit 计划**(1 commit):

- `feat(findings): enrich host field for cross-product correlation`

### 14.3 Hook C · 实时 syslog 接入(v0.7)

**目标**:从 stdin/file 升级到 syslog UDP 514 接收,接 systemd-journal / CloudWatch。

**改动范围**(Codex 自行决定):

- `src/ai_soc_agent/ingest.py` 新增 `SyslogUDPReceiver`(asyncio + `datagrams` protocol)
- `src/ai_soc_agent/cli.py` 新增 `--syslog --port 514` 启动选项
- `tests/test_syslog_receiver.py` —— mock UDP packet,验证解析 + 触发 correlation

**约束**(派活时再定,本文档仅描述方向):

- **不**绑 514 < 1024 端口(非 root 起不来),默认用 1514
- **不**改 v0.5 §15 CLI envelope

### 14.4 不要做的事

- ❌ 不改 `Finding` schema(共享契约,改了就破 v0.5 冻结)
- ❌ 不让 001 仓直接 import 002/003/etc(横向耦合,违反 §10 ProductAdapter 单向隔离)
- ❌ 不把规则写死在 `correlator.py` 的 if-else 里,必须走 v0.5 §8 RuleEngine
- ❌ 不打真外部 API(NVD / Okta),CI 不允许网络
- ❌ 不动 `tests/test_cli_envelope.py` —— §15 契约测试是冻结基线

### 14.5 验收清单

Codex 完工后跑:

```powershell
# 必须用绝对 Python + basetemp 隔离
& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m pytest tests/ `
  --basetemp=C:/pytest-tmp/001-phase2 `
  -o addopts= `
  -q --tb=short

# CLI envelope 必须保持
& 'C:\Users\15072\AppData\Local\Programs\Python\Python314\python.exe' `
  -m ai_soc_agent scan --input '{"source":"sshd","events":[...]}' --json
```

预期:≥ 95 passed(原 76 + Phase-2 新增 19);CLI envelope 仍是 `{"findings": [...], "summary": {...}}`。

---

**最近修订**: 2026-07-25 · Claude 把 PHASE-2.md 合并进 §14
**下次回看触发**: v0.6 启动 / Hook A/B/C 任一完工 / 跨产品 correlation 派活启动