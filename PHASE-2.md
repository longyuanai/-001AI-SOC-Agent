# 001AI-SOC-Agent · Phase-2 计划

> **本仓角色**: AI SOC 告警分析 Agent。`sshd` / `evtx` / `nginx` / `okta` 日志解析 + 攻击模式检测 + Finding 产出。
> **当前状态**: v0.6 §15 CLI Envelope 已实现,S4 worker 4 件套全绿,A 绿。
> **下一阶段**: v0.6+ 增强攻击覆盖与跨产品关联。

---

## 现状摘要(2026-07-25)

| 项 | 状态 |
|----|------|
| v0.1 LLM 集成 | ✅ |
| v0.5 Finding schema | ✅ |
| 4 种日志源解析(sshd / evtx / nginx / okta) | ✅ |
| CLI 子命令 `scan --input '<json>' --json` | ✅ |
| S4 worker 4 件套 | ✅ PASS |
| `tests/test_cli_envelope.py` 等 | ✅ |

---

## Phase-2 hooks

### Hook A · 攻击模式库扩充(派活 014-SOC-PATTERNS)

**目标**:覆盖 MITRE ATT&CK T1110(Brute Force)、T1078(Valid Accounts)、T1190(Exploit Public App) 等常见 SOC 场景。

**派活文档**:`014-SOC-PATTERNS.md`(待起草)

- 加 `src/ai_soc_agent/patterns/` 目录,每个模式 1 个文件
- 模式:`BruteForceBurstRule`(≥ 5 失败登录 / 60s)+ `GeoAnomalousLoginRule`(跨大洲登录) + `PrivilegeEscalationRule`(sudo 失败突变)
- 用 v0.5 §8 `RuleEngine` 跑,不写死代码
- 每模式 ≥ 3 个 test function 覆盖正常 + 边界 + 异常

**为什么 Phase-2**:
- 现在覆盖了基础 SSHD 日志
- 真实 SOC 场景需要 MITRE ATT&CK 全谱

### Hook B · 与 002 VULN 的 correlation(v0.6+)

**目标**:同一 IP 出 brute force + 已知 CVE,触发跨产品 correlation。

- 派活文档:`015-SOC-CROSS.md`(待起草)
- 不在本仓实现 correlation,只产 finding 让 `shared_llm_core.finding.host` 字段精准
- 与 000shared-llm-core 的 correlation rule 协同

### Hook C · 真实日志接入(可选 v0.7)

- 从 file/stdin 改成 syslog UDP 接收
- 解析 systemd-journal、CloudWatch Logs 等

---

## v1.0 路线图

```
v0.5 已冻结:CLI envelope + 4 source parser
v0.6: Hook A (MITRE ATT&CK 模式库 ≥ 10 个)
v0.7: Hook B (跨产品 correlation 配合)
v1.0: Hook C (实时 syslog 接收) + 与 SOAR 集成(n8n / Tines)
```

---

## 不要做的事

- ❌ 不要碰 Finding schema(那是共享契约)
- ❌ 不要让 SOC 仓直接调 002/003/004/etc(横向耦合,违规)
- ❌ 不要把规则写死在 if-else,必须用 v0.5 §8 RuleEngine

---

**最近修订**: 2026-07-25 · Claude 起草 Phase-2 计划
**下次回看触发**: v0.6 启动 / 新攻击模式接入 / Hook A 完成
