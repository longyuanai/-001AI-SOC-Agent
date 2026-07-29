# 001 AI-SOC-Agent · v0.1 TODO

> **项目状态**: v0.6 · 154 passed + 4 skipped(跨仓库)
> **共享接口**: [v0.1-contract.md](../../000shared-llm-core/docs/v0.1-contract.md) (已冻结)
> **派活模板**: [CODEX_INSTRUCTIONS.md](../../CODEX_INSTRUCTIONS.md)

---

## P0 · 本项目 v0.1 任务清单

| ID | 任务 | 状态 | 启动日 | 完成日 | 备注 |
|----|------|------|-------|-------|------|
| PARSER-001 | 加 Windows Event Log 解析器 | done | | 2026-07-24 | `parse_evtx_line`,iterparse 流式 |
| PARSER-002 | 加 Nginx access log 解析器 | done | | 2026-07-24 | `parse_nginx_line` |
| PARSER-003 | 加 Okta 登录日志解析器 | done | | 2026-07-24 | `parse_okta_record`,JSONL + 数组 |
| DETECT-001 | 关联规则 (同 IP 5 分钟 10 次失败 → 告警) | done | | 2026-07-25 | stream 模式默认值,见 `config.py` |
| API-001 | FastAPI server (接 ELK / Splunk) | done | | 2026-07-25 | `/ingest` `/alerts` `/health` |
| DOCKER-001 | Dockerfile | done | | 2026-07-25 | slim 多阶段 + 非 root |
| CI-001 | GitHub Actions (ruff + pytest) | done | | 2026-07-26 | 含 `tests/_contract_stub` 兜底 |

## P1 · 已知缺口

| ID | 任务 | 状态 | 备注 |
|----|------|------|------|
| ENRICH-001 | GeoIP 富化 (`extra.continent`) | pending | 没有它 `GeoAnomalousLoginRule` 在生产中永不触发 |
| ENRICH-002 | 凭据指纹 (`extra.password_hash`) | pending | 没有它凭据填充规则只有 cross_source 分支是活的 |
| PERSIST-001 | 告警落盘 | pending | 目前纯内存,重启即丢 |

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

- `RULE-MANIFEST-001` Sigma-compatible 规则清单与审计已于
  **2026-07-29 完成**；五个规则支持 `rules list` / `rules validate`。
- 下一项按 `docs/OPEN-SOURCE-FUSION-PLAN.md` 执行 `FIELD-MAP-001`；
  未经单独确认不提前实现 GeoIP、凭据指纹或持久状态。
- `SYSLOG-001` 实时 UDP syslog 接入明确延期到 **v0.7**；本轮不实现、不绑定端口。
