# 001 AI-SOC-Agent · v0.1 TODO

> **项目状态**: v0.5 · Phase-2 交付完成
> **测试**: `poetry run pytest -q` (跨仓库用例在只 clone 本仓库时自动 skip)
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)

---

## P0 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 完成日 | 备注 |
|----|------|------|-------|------|
| PARSER-001 | 加 Windows Event Log 解析器 | done | 2026-07-24 | `parse_evtx_line` |
| PARSER-002 | 加 Nginx access log 解析器 | done | 2026-07-24 | `parse_nginx_line` |
| PARSER-003 | 加 Okta 登录日志解析器 | done | 2026-07-24 | `parse_okta_record` |
| DETECT-001 | 关联规则 (同 IP 短窗口内多次失败 → 告警) | done | 2026-07-24 | `BruteForceBurstRule`；阈值见 `config.py` |
| API-001 | FastAPI server (接 ELK / Splunk) | done | 2026-07-24 | `/ingest` `/alerts` `/health` |
| DOCKER-001 | Dockerfile | done | 2026-07-24 | 多阶段 slim 镜像 |

## P0 · Phase-2 修复批次 (2026-07-25)

| ID | 任务 | 状态 | 备注 |
|----|------|------|------|
| FIX-001 | 5 条规则全部进 `/alerts` | done | 告警元数据下沉到 `SOCPattern`；`finding_to_alert` 不再静默丢弃 |
| FIX-002 | 每条规则支持多命中 | done | `count_windows` / `distinct_windows` 按分组各出一条 |
| FIX-003 | 阈值收敛到单一来源 | done | `config.py` 两个具名 profile |
| FIX-004 | 删掉死代码关联函数 | done | `detect_brute_force` / `detect_credential_stuffing` 移除，测试改测 `correlate()` |
| FIX-005 | `/ingest` 有界关联 + 稳定告警 id | done | 只关联 `MAX_RULE_WINDOW_SECONDS` 窗口；锁外跑关联 |
| FIX-006 | API 鉴权 | done | `AI_SOC_API_TOKEN` bearer token |
| FIX-007 | prompt 单一副本 | done | `prompts.py` 加载 yml，analyzer 里的硬编码副本删除 |
| FIX-008 | LLM 返回容错 | done | `AnalyzerError`，不再裸抛 `JSONDecodeError` |
| FIX-009 | `scan --log-type` | done | 非 sshd 输入不再静默解析成 0 事件 |
| FIX-010 | CI + 依赖声明 | done | `.github/workflows/ci.yml`；httpx / ruff / pyyaml 进 pyproject |
| FIX-011 | 混合时区批次崩溃 | done | `detect_patterns` 里 min/max 前统一按 UTC 归一 |
| FIX-012 | AUDIT S1 nit 1/2/3 全部清掉 | done | `--basetemp` 去掉；cli 顶层 import；`--log-type` 显式 |

### 已知未闭环

- `tests/integration/` 与 `tests/test_cli_envelope.py` 依赖 `000shared-integration`，
  只 clone 本仓库时 skip。CI 里靠 `SHARED_INTEGRATION_REPO` 变量启用。
- nginx / okta 的 401 事件 `action` 是 `http_request`，不含 `login`，因此不会触发
  T1110。要覆盖 Web 登录爆破需要在解析器里区分登录端点，留到 v0.6。

---

## 派活模板（复制即可）

发给 Codex 时,把这个模板 + 上面 issue 表里挑的一行 ID 拼起来:

```
[{ISSUE_ID}] 001 AI-SOC-Agent · {一句话}

## 背景
- 项目: 001 AI-SOC-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\001AI-SOC-Agent
- 接口契约: 000shared-llm-core/docs/v0.1-contract.md (已冻结)

## 必须做的事
1. <具体动作 1,含文件路径>
2. <具体动作 2>
3. <具体动作 3>

## 验收
- [ ] pytest 全绿
- [ ] 新增测试 ≥ N 个
- [ ] CLI smoke test 通过 (粘贴输出)
- [ ] 改动文件清单 (git diff --stat)

## 回报格式
**ID**: <ISSUE-ID>
**Files changed**: <列表>
**Tests**: X/X passed
**CLI smoke**: <输出片段>
**Deviations**: <如有,说明原因>
```

---

## 复盘节奏

- 每周一 09:00: 跑 `pytest` 全量,状态写到本表
- 每周五 17:00: review 完成的 issue,标 done
- 每月 1 号: 检查 shared-llm-core 是否有 breaking change

---

## Phase-2 后续

- `SYSLOG-001` 实时 UDP syslog 接入明确延期到 **v0.7**；本轮不实现、不绑定端口。
