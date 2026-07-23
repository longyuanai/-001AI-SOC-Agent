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