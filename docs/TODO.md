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
| FIX-013 | nginx Web 登录爆破不可见 | done | `is_login_endpoint` + 只认 POST/PUT/PATCH → `action="web_login"`，T1110 覆盖 Web |
| FIX-014 | sshd 只认 password 认证 | done | `Failed`/`Accepted` 泛化到任意 auth method，`extra.auth_method` 记录 |
| FIX-015 | syslog 缺年份导致跨年断窗 | done | `_parse_ts` 按 `now` 推断年份，未来 >1 天读作去年 |
| FIX-016 | 插件 entry point 无人校验 | done | `tests/test_pattern_entry_points.py` 保证 pyproject 声明与 `PATTERN_TYPES` 不漂移 |
| FIX-017 | nginx 登录路径写死 | done | 收进 `config.login_path_segments()`，`AI_SOC_LOGIN_PATH_SEGMENTS` 追加自定义路由 |
| FIX-018 | `severity_hint` 可能与 `severity_default` 不一致 | done | 改为派生属性；顺带删掉我自己引入的死方法 `matched_events` |

### 已知未闭环

- `tests/integration/` 与 `tests/test_cli_envelope.py` 依赖 `000shared-integration`，
  只 clone 本仓库时 skip。CI 里靠 `SHARED_INTEGRATION_REPO` 变量启用。
- sshd 的 `Invalid user X from IP` 行**故意不解析**：sshd 通常同时打这一行和
  `Failed password for invalid user X`，两条都收会把失败次数翻倍、等效把阈值砍半。
  要用它需要先做同一次认证尝试的去重（按 pid + 时间聚合），留到 v0.6。
- `pyproject.toml` 的 `longyuanai.soc_patterns` entry point **本仓库不加载**，
  消费方在 suite 侧。已加一致性测试防漂移，但"谁来加载"仍需 suite 层确认；
  如果确实无人消费，应当删掉这段声明。

---

## P0 · v0.7 待办（下一批派活）

优先级依据见 `tech-spec.md` §16。**每张卡都是可直接粘给 Codex 的完整派活单。**

| ID | 任务 | 价值 | 状态 |
|----|------|------|------|
| SOC-LLM-TRIAGE | LLM 对规则命中做二次研判 | 最高 | pending |
| SOC-GEOIP | 富化 `extra.continent`，让 T1078 可用 | 高 | pending |
| SOC-ALERT-TTL | 告警老化 / 上限 | 高 | pending |
| SOC-EVAL | 标注集 + precision/recall 评测 | 高 | pending |
| SOC-REDACT | evidence 脱敏开关 | 中 | pending |
| SOC-RULE-DSL | YAML 自定义规则 | 中 | pending |
| SOC-SYSLOG | syslog UDP 接收（Hook C） | 中 | pending |
| SOC-SSHD-DEDUP | 同次认证尝试去重 | 低 | pending |

### 卡片 1 · SOC-LLM-TRIAGE（建议先做这个）

```
[SOC-LLM-TRIAGE] 001 AI-SOC-Agent · 让 LLM 对规则命中的 Finding 做二次研判

## 背景
- 项目: 001 AI-SOC-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\001AI-SOC-Agent
- 问题: 本产品定位是"SOC 的 AI 副驾驶"，但目前 LLM 完全没有参与告警分级。
  代码里有两条互不相交的路径（见 tech-spec.md §4）：
    路径 A `scan` / `/ingest` —— 纯确定性规则，产 Finding，不调 LLM
    路径 B `analyze`          —— 纯 LLM，产 Markdown 报告，不看规则
  tech-spec §14.1 当初写的 "SOCPattern 提供 LLM 评估 hook" 从未实现。

## 必须先 Read
1. docs/tech-spec.md（重点 §4 双路径、§7 规则清单、§15 冻结契约）
2. docs/TODO.md
3. 000shared-llm-core/docs/v0.1-contract.md
4. 000shared-llm-core/src/shared_llm_core/__init__.py
5. src/ai_soc_agent/patterns/base.py（SOCPattern.evaluate 现有形状）

## 必须做的事
1. 新建 src/ai_soc_agent/triage.py：
   - triage_findings(findings, router, *, max_findings=10) -> list[Finding]
   - 对每条 Finding 调一次 STANDARD tier，问"这是真攻击还是误报"
   - LLM 只允许**下调** confidence 和补 metadata，**不允许**改 severity /
     host / evidence（防幻觉污染取证字段）
   - 返回新的 Finding（Finding 是 frozen，用 dataclasses.replace）
2. 新建 prompts/finding_triage/v1.yml —— 唯一 prompt 副本，禁止在 py 里再写一份
   输出 JSON: {"verdict": "true_positive"|"false_positive"|"unclear",
                "confidence_delta": -0.5..0.0, "rationale": "一句话"}
3. CLI `scan` 加 --triage 开关（默认关）。开启时才 import shared_llm_core，
   保持不带 provider 的环境仍能跑 scan
4. metadata 里加 "triage": {"verdict": ..., "rationale": ..., "model": ...}
5. 加 tests/test_triage.py（≥ 8 个测试，全部用 conftest 的 stub_router）：
   - 误报判定会下调 confidence
   - LLM 想上调 confidence 时被忽略
   - LLM 想改 severity / host 时被忽略
   - LLM 返回畸形 JSON 时保留原 Finding 不崩
   - --triage 关闭时不发生任何 LLM 调用
   - max_findings 截断生效

## 必须满足的约束
- 不改 Finding schema（共享冻结契约）
- 不改 §15 冻结契约测试；envelope 顶层仍然只有 "findings" 一个键
- triage 失败（超时 / 畸形 / 无 provider）必须降级为"保留原 Finding"，绝不能让
  scan 整体失败 —— 确定性检测的可用性高于 LLM 增强
- prompt 走 prompts/<name>/<version>.yml
- 不加 --basetemp

## 不要做的事
- 不要让 LLM 参与"是否命中"的判定（那会让检测不可复现）
- 不要在 /ingest 路径上默认开启（同步 HTTP 里串 LLM 调用会拖垮吞吐）

## 验收
- [ ] pytest 全绿（当前基线 178 passed + 4 skipped，只增不减）
- [ ] ruff check src tests 全绿
- [ ] 新增测试 ≥ 8
- [ ] CLI smoke: scan --triage 在无 provider 时优雅降级（粘输出）
- [ ] git diff --stat
```

### 卡片 2 · SOC-GEOIP

```
[SOC-GEOIP] 001 AI-SOC-Agent · 富化 extra.continent，让 T1078 在真实数据上可用

## 背景
- GeoAnomalousLoginRule（001.mitre.t1078.geo-anomalous-login）已实现并有测试，
  但它依赖 extra.continent，而**没有任何解析器产出这个字段** ——
  只有手工构造的事件能触发，真实日志跑不出来。见 tech-spec.md §7 覆盖缺口。

## 必须做的事
1. 新建 src/ai_soc_agent/geoip.py：
   - continent_of(ip: str) -> str | None
   - 离线查表，优先读 MaxMind GeoLite2-Country.mmdb（若已配置），
     否则回退到内置的 IANA 顶层网段 → 大洲粗表
   - 路径由 AI_SOC_GEOIP_DB 环境变量指定；未配置时用回退表，不报错
2. 在 config.py 登记 AI_SOC_GEOIP_DB，并在 tech-spec §6 配置表补一行
3. 解析器富化：actor 是公网 IP 时写入 extra.continent
   - 私网 / 环回 / 保留地址不写（RFC1918 无意义）
4. samples/mitre/T1078.log 增补一条真实格式的 okta 记录，证明端到端可触发
5. 加 tests/test_geoip.py（≥ 6 个测试）：
   - 私网地址不产出 continent
   - 未配置 mmdb 时回退表可用且不抛异常
   - mmdb 路径不存在时降级而非崩溃
   - 富化后 GeoAnomalousLoginRule 能在解析出的事件上命中

## 必须满足的约束
- **不打网络**（CI 禁网），只能离线查表
- 不引入必需的新依赖：maxminddb 若使用必须是可选依赖，缺失时回退
- 富化只写 extra，不改 NormalizedEvent 字段

## 验收
- [ ] pytest 全绿（基线只增不减）+ ruff 全绿
- [ ] 新增测试 ≥ 6
- [ ] CLI smoke: 用富化后的 okta 样本跑出 geo_anomaly finding（粘输出）
```

### 卡片 3 · SOC-ALERT-TTL

```
[SOC-ALERT-TTL] 001 AI-SOC-Agent · 告警老化与上限

## 背景
- server.py 的 store.alerts 是个只增不减的 dict：没有 TTL、没有上限、没有关闭状态。
  长跑进程内存会无限增长。事件缓冲已有 max_events 上限，告警侧没有对应机制。
  见 tech-spec.md §8 / §13。

## 必须做的事
1. config.py 加 ALERT_TTL_SECONDS（默认 86400）与 MAX_ALERTS（默认 5000）
2. server.py：
   - Alert 加 status 字段（open | aged_out），或在 store 侧记录 last_updated
   - ingest 时淘汰超过 TTL 的告警；超过 MAX_ALERTS 时按 last_seen 最旧优先淘汰
   - /alerts 加 ?status= 过滤，默认只返回 open
3. /health 增加 alerts_aged_out 计数
4. 加测试（≥ 6）：TTL 淘汰、上限淘汰、淘汰不影响同 id 告警重新出现、
   /alerts 默认不返回 aged_out

## 必须满足的约束
- 不改 Alert.to_dict() 已有键的含义（/alerts 是对外形状）；新增键可以
- 淘汰逻辑要在锁内，但不要把关联计算也挪回锁内

## 验收
- [ ] pytest 全绿 + ruff 全绿，新增测试 ≥ 6
- [ ] 构造 6000 条告警验证内存有界（粘输出）
```

### 卡片 4 · SOC-EVAL

```
[SOC-EVAL] 001 AI-SOC-Agent · 标注数据集 + precision/recall 评测脚本

## 背景
- tech-spec.md §11 承诺 precision ≥ 85% / recall ≥ 80%，但既没有标注语料也没有
  评测脚本，这两个指标目前无法验收。**在补齐本卡之前，不要派任何"提升
  precision"类任务** —— 那是不可验收的。

## 必须做的事
1. 新建 evaluation/ 目录：
   - dataset/*.jsonl —— 每行 {"events": [...], "expected_alert_kinds": [...], "note": "..."}
   - 至少 20 条：涵盖 5 条规则各自的真阳性、易混淆的真阴性（正常运维批量登录、
     CI 跑批、监控探针）
2. scripts/evaluate.py：
   - 跑 detect_patterns，与 expected 比对，输出 per-rule precision / recall / F1
   - --json 输出机器可读结果
3. 加 tests/test_evaluation.py：数据集 schema 合法、脚本能跑、当前分数不低于
   记录在案的基线（基线写进 evaluation/BASELINE.md）
4. tech-spec.md §11 把"当前可测性"从 ❌ 改为 ✅ 并写上实测值

## 必须满足的约束
- 标注数据必须是合成的，不能含真实客户日志
- 评测不调 LLM（评的是确定性规则层）

## 验收
- [ ] python scripts/evaluate.py 输出 per-rule 指标（粘输出）
- [ ] pytest 全绿 + ruff 全绿
```

### 其余卡片

`SOC-REDACT` / `SOC-RULE-DSL` / `SOC-SYSLOG` / `SOC-SSHD-DEDUP` 的背景与约束见
`tech-spec.md` §16 与 §13，派活时按上面 4 张卡的结构展开即可。

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
