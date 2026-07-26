# AUDIT · 001 AI-SOC-Agent · S2 缺陷修复批次

**审计日期**: 2026-07-25
**审计人**: Claude
**范围**: 全仓库缺陷诊断后的修复批次 (FIX-001 ~ FIX-018，见 `docs/TODO.md`)

---

## 结果: **PASS**

## 10 项 checklist

| # | 项 | 结果 | 备注 |
|---|----|------|------|
| 1 | 接口契约 | PASS | 未改 `000shared-llm-core`；只消费 `Finding` / `Rule` / `RuleContext` / `RuleEngine` / `RuleRegistry` / `LLMRouter`，无新增依赖面 |
| 2 | 技术方案 | PASS | `docs/tech-spec.md` 未改；`docs/TODO.md` 从"全 pending"更新为真实状态 |
| 3 | 测试 | PASS | 178 passed + 4 skipped(跨仓库用例)。修复前为 12 个 collection error(缺 sibling 仓库) |
| 4 | CLI smoke | PASS | `scan` / `--log-type` / bare-option 分发 / 多 actor 多 finding / nginx Web 爆破全部实测通过 |
| 5 | 跨项目隔离 | PASS | 仅改动本仓库 |
| 6 | 依赖管理 | PASS | 新增 `pyyaml`(prompt 加载)、dev 的 `httpx`(测试已在用但未声明)、`ruff`(已配置但未声明) |
| 7 | 代码质量 | PASS | `ruff check src tests` 全绿；无 hardcoded 凭据；Dockerfile 无 `ENV`/`ARG` 形式的密钥 |
| 8 | Prompt 模板 | PASS | `prompts/incident_triage/v1.yml` 成为唯一副本，由 `prompts.py` 加载 |
| 9 | 审计日志 | N/A | 本批次不改 LLM 审计路径 |
| 10 | 回报格式 | PASS | 本文件 |

## 修复要点

- **检测覆盖**: 5 条 MITRE 规则此前只有 2 条能进 `/alerts`（其余 3 条因缺
  `finding_metadata` 被 `_finding_to_alert` 静默丢弃）。告警元数据下沉到
  `SOCPattern.finding_metadata`，`finding_to_alert` 改为降级而非丢弃。
- **多命中**: 规则原本 return-on-first，一批日志里 N 个攻击源只报 1 条。改为
  `count_windows` / `distinct_windows` 按分组各出一条。实测 3 个 IP → 3 条 finding。
- **阈值一致性**: 阈值从 3 处字面量收敛到 `config.py` 的两个具名 profile
  (`detection_facts()` 一次性扫描 / `STREAMING_PROFILE` 流式 `/ingest`)，
  差异从"意外漂移"变成"有文档的显式选择"。
- **潜在崩溃**: `detect_patterns` 对混合 naive/aware 时间戳的批次会
  `TypeError`（`/ingest` 收 ELK + Splunk 混合流即触发）。已在比较前统一归一到 UTC。
- **`/ingest` 成本与重复**: 原本每次请求持锁全量重跑 10k 事件关联，且告警 id 由
  窗口边界哈希得来 → 重放同一批事件会不断产生新告警。现在只关联
  `MAX_RULE_WINDOW_SECONDS` 窗口、关联在锁外执行、id 由 `(type, actor)` 派生。
- **鉴权**: `AI_SOC_API_TOKEN` 生效时 `/ingest` `/alerts` 需要 bearer token；
  `/health` 恒开放以便容器探针。未设置时启动打 warning。
- **死代码**: `detect_brute_force` / `detect_credential_stuffing` 约 150 行无人调用，
  但 `test_correlator.py` / `test_credential_stuffing.py` 在测它们 —— 覆盖率好看、
  实际生产路径无覆盖。已删除，测试改测 `correlate()`。

## 解析器复查（第二轮，`parsers.py` 399 行首轮未细读）

- **Web 登录爆破完全不可见**: nginx 事件的 `action` 恒为 `http_request`，不含
  `login` token，因此 T1110 永远不会在 Web 日志上触发 —— 对一个 SOC 产品来说是
  整类攻击的盲区。新增 `is_login_endpoint()`：路径命中认证段（login / signin /
  session / oauth / token ...）**且**动词是 POST/PUT/PATCH 才记为 `web_login`。
  `GET /login` 是加载表单不是认证尝试，静态资源（`/static/login.css`）排除。
- **sshd 只认 password**: `Failed password` / `Accepted password` 写死，
  `Failed publickey` 被静默丢弃。纯密钥认证的服务器上，撞私钥的爆破一条都看不到。
  已泛化到任意 auth method，并把方法名记进 `extra.auth_method`，便于区分
  密码喷洒和密钥探测。
- **syslog 跨年断窗**: `_parse_ts` 用 `datetime.now().year` 盖章。1 月读 12 月的
  日志会把事件放到 11 个月后的未来，跨年那一刻的爆破被拆成相隔一年的两半，
  任何时间窗都不会触发。已改为按参考时刻推断：未来超过 1 天的读作去年。
  Feb 29 落到非闰年时保留当年读数。
- **`Invalid user X from IP` 刻意不解析**: sshd 通常对同一次尝试同时打这一行和
  `Failed password for invalid user X`，两条都收会把失败次数翻倍、等效把阈值砍半。
  记录在 `docs/TODO.md` 的未闭环项，需要先做同次尝试去重。

## 声明与死符号复查（第三轮）

- **插件 entry point 无人校验**: `pyproject.toml` 在 `longyuanai.soc_patterns` 下
  声明了全部 5 条规则，但本仓库没有任何代码读这个 group（`ENTRY_POINT_GROUP` 只是
  一个导出的字符串常量）。消费方在 suite 侧，意味着改名或新增规则时声明会静默漂移，
  真正加载它的人在运行时才发现。**没有擅自改变加载方式**（谁消费属于 suite 层决定），
  而是加了一致性测试：每条声明必须能解析成 `SOCPattern` 子类，且集合与 `PATTERN_TYPES`
  完全相等。已实测两种漂移（删掉一条、类名写错）都会让测试变红。
- **`severity_hint` 会说谎**: 原本是类属性硬写 `"high"`，任何把 `severity_default`
  调低的子类仍然报 "high"。改成从 `severity_default` 派生的属性，两者不可能再分叉，
  同时保留外部introspection 的接口。
- **`matched_events` 是我自己引入的死代码**: 上一轮为兼容单命中调用者加的，实际
  没有任何调用点。既然本次审计的主线之一就是清死代码，一并删掉。
- **nginx 登录路径写死**: `_LOGIN_SEGMENTS` 是模块级常量，自定义登录路由
  (`/j_security_check` 等) 无法识别。收进 `config.login_path_segments()`，
  由 `AI_SOC_LOGIN_PATH_SEGMENTS` 追加（只增不减，默认段永远生效），
  与本次确立的"所有调参集中在 config.py"原则一致。

## S1 遗留 nit 关闭情况

| Nit | 状态 |
|-----|------|
| Nit 1 · `--basetemp=.pytest-tmp` 在 Windows 上导致 7 个 ERROR | 已关闭，`addopts` 去掉该覆盖 |
| Nit 2 · `cli.py` 函数内 import `os` / `LLMRouter` | 已关闭，`os` 提到顶层；`LLMRouter` 保留在 `analyze` 内并注明原因（API 镜像不需要 LLM provider） |
| Nit 3 · `--log-type` 默认值可能误判 | 已关闭，`scan` 新增 `--log-type`，显式覆盖 payload 的 `source` |

## 阻塞问题

- 无。

## 未闭环（非本批次可解）

- 本仓库对 `../000shared-llm-core` 是 `path` 依赖，独立 clone 无法安装或跑测试。
  已做的是：CI 按可配置的 repo 变量检出 sibling 仓库并在缺失时给出可执行的报错；
  跨仓库测试改为 skip 而非 collection error。真正的解法（发包或 submodule）需要
  suite 层决策。
