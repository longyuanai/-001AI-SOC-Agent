# 让 Codex 写代码的标准指令模板

> **目的**: 给 Codex（或其他 AI agent）派活时，复制对应模板、改 ID 即可
> **协作模式**: 我（人工）出 spec + 模板，Codex 写代码 + 测试，每个 issue 一来一回

---

## 通用模板（任何 issue 都套这个）

```
[TASK-ID] <项目名> · <一句话>

## 背景
- 项目: <006AI-Firmware-Security-Agent 等>
- 工作目录: <E:\001项目\000开发\003AI+网络安全\XXX>

## ⚠️ 必须先 Read 的 6 个文件（跨项目依赖）
1. <E:\...\XXX\docs\tech-spec.md>             — 本项目业务方案
2. <E:\...\XXX\docs\TODO.md>                   — 本项目 issue 清单 + 上下文
3. <E:\...\000shared-llm-core\docs\v0.1-contract.md>  — 共享接口契约 (已冻结!)
4. <E:\...\000shared-llm-core\src\shared_llm_core\__init__.py>  — 共享 API 真实导出
5. <E:\...\XXX\src\<pkg>\config.py>            — 阈值/抑制名单唯一事实源（如该项目有）
6. <E:\...\XXX\tests\_contract_stub\README.md> — 契约替身边界（如该项目有）

(共享内核不在你工作目录下,但你必须先 Read 才能正确 import)

## ⚠️ 环境前提：三仓库必须并排存在

本套件是多仓库 path 依赖，不是单仓库项目：

    003AI+网络安全\
    ├── 000shared-llm-core\      ← pyproject.toml 里的 path 依赖
    ├── 000shared-integration\   ← 部分测试引用
    └── XXX\                     ← 你的工作目录

只 clone 单个仓库的话 `poetry install` 会直接失败。开工前先确认：

    poetry run python -c "import shared_llm_core; print(shared_llm_core.__file__)"

输出必须指向真实的 `000shared-llm-core\src\`。如果指向
`tests\_contract_stub\`，说明真包缺失，你正在对着**替身**开发 —— 立即停止并
报告，不要继续，也不要改替身让测试变绿。

## 必须做的事
1. <具体动作 1，含文件路径>
2. <具体动作 2>
3. <具体动作 3>

## 必须满足的约束
- **接口契约见 v0.1-contract.md，**不要改 shared-llm-core 的 schema**
- 只 import 使用 `shared_llm_core`,不复制其代码进本项目
- 用现有 prompt 模板结构（prompts/<name>/<version>.yml）
- 测试用 stub router / httpx.MockTransport（不能真调 LLM）
- Windows 兼容：用 pathlib.Path，不写死斜杠
- 阈值/开关写进该项目的 config.py，不要散落在规则里写死数字

## 不要做的事
- 不要改 tech-spec.md（除非该 issue 本身是改 spec）
- 不要动其他项目的代码
- 不要改 000shared-llm-core/ 任何文件 (它是冻结的内核)
- 不要装新依赖（除非 issue 显式批准）
- 不要改 audit 后端格式
- **不要加 `--basetemp=.pytest-tmp`**（本模板旧版本要求过，已废除 —— 它把 tmp
  目录钉到仓库内，正是 AUDIT/001-S1.md Nit 1 里那 7 个 Windows 文件锁 ERROR
  的根因，也会让并行跑测试互相踩。让 pytest 自己管 tmp_path）
- 不要改 tests/_contract_stub/ 来让测试变绿（那是 CI 兜底，不是开发目标）

## 验收（Codex 完成后必须达到）
- [ ] pytest 全绿（X/X passed）
- [ ] 新增测试 ≥ N 个
- [ ] CLI smoke test 通过（粘贴输出）
- [ ] 没有 lint error
- [ ] 改动文件清单（git diff --stat）

## 回报格式
完成后用这个格式回复：

**ID**: <TASK-ID>
**Files changed**: <列表>
**Tests**: X/X passed
**CLI smoke**: <输出片段>
**Deviations**: <如有，说明原因>
**Open questions**: <如有，列出>
```

---

## 实例 1：接真实 NVD API（P0-1 · CVE-001）

```
[CVE-001] 006 AI-Firmware-Security-Agent · 接真实 NVD API 替换 mock

## 背景
- 项目: 006 AI-Firmware-Security-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\006AI-Firmware-Security-Agent
- 接口契约: 000shared-llm-core/docs/v0.1-contract.md（已冻结）
- 当前状态: cve_db.py 用内置 _KNOWN_VULN mock

## 必须做的事
1. 在 src/ai_firmware_agent/ 新建 nvd.py：
   - nvd_lookup(component: Component, *, api_key: str | None = None) -> list[CveRecord]
   - 调 https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:...
   - 解析 CPE 格式（vendor:product:version）
   - 失败 fallback 到 mock_lookup()
2. 在 analyzer.py 的 match_components() 里加参数：lookup_fn=mock_lookup 默认
3. CLI 加 --nvd-api-key 选项
4. prompts/ 加 enrichment_nvd.yml（用 NVD 数据时改用不同 prompt）
5. 加 tests/test_nvd.py：用 httpx.MockTransport 返回假 NVD JSON

## 必须满足的约束
- 接口契约见 v0.1-contract.md
- 测试用 httpx.MockTransport，不真打 NVD
- 没有 NVD API key 时 fallback 到 mock_lookup，不能崩
- Windows 兼容

## 不要做的事
- 不要删 mock_lookup（保留作 fallback + 测试用）
- 不要改 CveRecord dataclass 字段
- 不要接 EPSS/KEV（这是 CVE-002 / CVE-003 的事）

## 验收
- [ ] pytest 全绿
- [ ] 新增 ≥ 6 个测试
- [ ] CLI smoke: firmware-agent scan --demo --use-nvd 跑通
- [ ] 没有 NVD key 时打印 warning 并 fallback
```

---

## 实例 2：加 Windows Event Log 解析器（P0-3 · PARSER-001）

```
[PARSER-001] 001 AI-SOC-Agent · 加 Windows Event Log 解析器

## 背景
- 项目: 001 AI-SOC-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\001AI-SOC-Agent
- 当前 parsers.py 只有 sshd（OpenSSH auth.log）

## 必须做的事
1. 在 src/ai_soc_agent/parsers.py 加 parse_evtx_line(line: str) -> NormalizedEvent | None
   - 支持 XML 格式（Windows Event Log 导出）
   - 至少识别 Event ID 4625（登录失败）、4624（登录成功）、4648（显式凭据）
2. 在 src/ai_soc_agent/parsers.py 加 parse_evtx_file(path: str) -> list[NormalizedEvent]
3. CLI 加 --log-type {sshd|evtx} 选项
4. samples/ 加 samples/win_logon_4625.xml（至少 5 行假数据）
5. 加 tests/test_evtx.py：覆盖 3 个 Event ID

## 必须满足的约束
- 不引入新依赖（用标准库 xml.etree）
- 返回值类型与 parse_line 一致（NormalizedEvent）
- Event ID 解析失败返回 None，不抛异常
- Windows 兼容

## 不要做的事
- 不要改 sshd parser
- 不要碰 analyzer / reporter
- 不要引入 evtx 包（那是真 .evtx 二进制，PoC 阶段用 XML 导出）

## 验收
- [ ] pytest 全绿
- [ ] 新增 ≥ 5 个测试
- [ ] CLI smoke: ai-soc analyze -i samples/win_logon_4625.xml -o report.md
- [ ] 报告里能看到 Windows Event ID 信息
```

---

## 实例 3：Docker 化（P0-1 · DOCKER-001）

```
[DOCKER-001] 006 AI-Firmware-Security-Agent · 加 Docker 支持

## 必须做的事
1. 项目根目录加 Dockerfile：
   - 基础镜像 python:3.11-slim
   - 先 COPY ../000shared-llm-core 再 poetry install
   - ENTRYPOINT ["firmware-agent"]
2. 加 docker-compose.yml：
   - service firmware-agent
   - 挂载 ./samples:/app/samples
   - 环境变量 LLM_PROVIDERS / NVD_API_KEY
3. 加 .dockerignore
4. README.md 加 Docker 使用章节

## 必须满足的约束
- 镜像 < 500 MB
- poetry install 用 --no-dev
- 不在镜像里留 .git / tests / __pycache__

## 验收
- [ ] docker build . 成功
- [ ] docker run ... firmware-agent scan --demo 输出正常
- [ ] docker-compose up 跑通
```

---

## 实例 4：GeoIP 富化（P1 · ENRICH-001）· 待派

> **为什么要做**: `GeoAnomalousLoginRule`(T1078) 读 `extra["continent"]`，但**没有
> 任何解析器产出这个字段** —— 只有手搓的 `samples/mitre/T1078.log` 有。这条规则
> 在生产中永远不会触发。

```
[ENRICH-001] 001 AI-SOC-Agent · 加 GeoIP 富化让 T1078 规则真正可用

## 背景
- 项目: 001 AI-SOC-Agent
- 路径: E:\001项目\000开发\003AI+网络安全\001AI-SOC-Agent
- 现状: geo_anomaly.py 依赖 extra["continent"]，无来源 → 规则是死的

## 必须做的事
1. 新建 src/ai_soc_agent/enrichment.py：
   - enrich_geo(event: NormalizedEvent) -> NormalizedEvent
   - 查不到 / 私网地址 → 原样返回，不抛异常、不写空值
   - 数据源用本地 MaxMind GeoLite2 mmdb，路径从 SOC_GEOIP_DB 读
2. 在 parse_file / iter_file 出口挂一个可选 enrich 钩子（默认关闭）
3. CLI 加 --enrich-geo；server 用 SOC_GEOIP_DB 存在与否自动决定
4. samples/ 加一条跨大洲的真实格式样例
5. tests/test_enrichment.py：私网、查不到、正常命中、db 缺失四种情况

## 必须满足的约束
- 没有 mmdb 文件时整条链路照常工作，只是不富化（不能崩、不能报错退出）
- 不引入需要联网的 GeoIP 服务（离线优先）
- 新依赖需在本 issue 显式批准：geoip2（如用别的方案先说明）
- 富化只往 extra 里加字段，不改 NormalizedEvent 的固有字段

## 不要做的事
- 不要改 geo_anomaly.py 的判定逻辑（它已经对了，缺的是数据）
- 不要改 Finding schema

## 验收
- [ ] pytest 全绿
- [ ] 新增 ≥ 6 个测试
- [ ] 无 mmdb 时 CLI 正常跑完并 warning
- [ ] 有 mmdb 时 samples 里的跨洲样例能触发 T1078 finding
```

---

## 实例 5：凭据指纹（P1 · ENRICH-002）· 待派

> **为什么要做**: `CredentialStuffingRule` 的默认分支读
> `extra["password_hash"] / credential_hash / password_fingerprint`，同样**无任何
> 解析器产出**。目前只有 `credential_stuffing_mode="cross_source"` 分支是活的，
> 而 CLI 的 scan 路径不传这个 fact —— 即 CLI 上这条规则完全不触发。

```
[ENRICH-002] 001 AI-SOC-Agent · 凭据指纹字段落地 + CLI 打通 cross_source

## 背景
- 项目: 001 AI-SOC-Agent
- 现状: credential_stuffing.py 有两个分支，默认分支缺数据源，
  cross_source 分支 CLI 不传 fact → 两条路都不通

## 必须做的事
1. 明确 password_hash 的来源与格式，写进 docs/tech-spec.md 的一个小节
   （上游 WAF/IdP 提供，还是本仓计算？如果本仓算，绝不能存明文口令）
2. cli.py 的 scan_payload：允许 payload 传 credential_stuffing_mode，
   默认给 "cross_source"，让 CLI 路径至少有一条分支是活的
3. tests/：CLI 传 cross_source 能出 finding；默认分支用带 password_hash 的
   fixture 覆盖
4. README 的 Detection tuning 表加对应说明

## 必须满足的约束
- 绝不落盘、绝不进日志、绝不进 evidence 明文口令或可逆凭据
- 指纹只做等值比较，不做还原
- 沿用 config.py 的阈值，不写死

## 不要做的事
- 不要改 Finding schema
- 不要为了让默认分支通过就伪造 password_hash

## 验收
- [ ] pytest 全绿
- [ ] 新增 ≥ 5 个测试
- [ ] CLI smoke: 跨源失败样例能出 credential_stuffing finding
- [ ] tech-spec 里写清 password_hash 的产生方与格式
```

---

## 给 Codex 的元指令（写进 system prompt）

```
你是 Codex,负责 longyuanai AI Security Agent Suite 的 v0.1 开发。

工作规则:
1. 每个任务是一个独立 issue,按 ID 跟踪(例: CVE-001, PARSER-001)
2. 开始前先 Read tech-spec.md + v0.1-contract.md,确认理解
3. 一次只做一个 issue,完成后等下一个
4. 不要跨项目改动,不要改接口契约
5. 测试用 stub router / httpx.MockTransport,不能真调外部 API
6. Windows 优先兼容(pathlib.Path;不要设 --basetemp,用 pytest 的 tmp_path)
7. 完成后用标准回报格式回复(见 CODEX_INSTRUCTIONS.md 末尾)

边界:
- 共享内核:000shared-llm-core 由我(人类)维护,你只能调用不能改
- 技术方案:tech-spec.md 是合同,改动需要新 issue
- 跨项目接口:任何破坏性变更 = blocking,要先讨论
- 三仓库并排:开工前确认 shared_llm_core 来自真包而非 tests/_contract_stub
```

---

## 复盘模板（Codex 完成后用）

```
## <TASK-ID> 复盘

**任务**: <一句话>
**耗时**: <X 分钟 / 小时>
**Files**: <N 个文件,行数 +N/-N>
**Tests**: <新增 X / 总 X>
**意外**: <遇到过的问题 1-2 句>
**建议**: <下次如何更快>
**Blocker**: <是否有需要人类决策的>

下一步: <接 CVE-002 / 暂停 / 等>
```

---

## 速查表（贴墙上）

| Issue 类型 | 模板 ID | 平均耗时 |
|-----------|---------|---------|
| 接外部 API | `<NAME>-001` | 30-60 分钟 |
| 加解析器 | `PARSER-NNN` | 15-30 分钟 |
| 加测试 | `TEST-NNN` | 10-20 分钟 |
| Docker | `DOCKER-NNN` | 20-30 分钟 |
| UI | `UI-NNN` | 1-2 小时 |
| 文档 | `DOC-NNN` | 10-15 分钟 |
| 数据富化 | `ENRICH-NNN` | 40-60 分钟 |

每个 issue 单次 Codex 会话 ≤ 2 小时。超过 = 拆分。

---

## 变更记录

- **2026-07-26**: 废除 `--basetemp=.pytest-tmp` 约束（AUDIT/001-S1.md Nit 1 的根
  因）；必读清单加 `config.py` 与契约替身 README；补三仓库并排的环境前提与自检
  命令；新增 ENRICH-001 / ENRICH-002 派活单。实例 2 (PARSER-001) 已于
  2026-07-24 交付，保留作格式参考。