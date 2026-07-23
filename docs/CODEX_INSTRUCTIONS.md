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

## ⚠️ 必须先 Read 的 4 个文件（跨项目依赖）
1. <E:\...\XXX\docs\tech-spec.md>             — 本项目业务方案
2. <E:\...\XXX\docs\TODO.md>                   — 本项目 issue 清单 + 上下文
3. <E:\...\000shared-llm-core\docs\v0.1-contract.md>  — 共享接口契约 (已冻结!)
4. <E:\...\000shared-llm-core\src\shared_llm_core\__init__.py>  — 共享 API 真实导出

(共享内核不在你工作目录下,但你必须先 Read 才能正确 import)

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
- pytest 加 pytest.ini 或 pyproject.toml 里 --basetemp=.pytest-tmp

## 不要做的事
- 不要改 tech-spec.md（除非该 issue 本身是改 spec）
- 不要动其他项目的代码
- 不要改 000shared-llm-core/ 任何文件 (它是冻结的内核)
- 不要装新依赖（除非 issue 显式批准）
- 不要改 audit 后端格式

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
- 加 --basetemp=.pytest-tmp

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

## 给 Codex 的元指令（写进 system prompt）

```
你是 Codex,负责 longyuanai AI Security Agent Suite 的 v0.1 开发。

工作规则:
1. 每个任务是一个独立 issue,按 ID 跟踪(例: CVE-001, PARSER-001)
2. 开始前先 Read tech-spec.md + v0.1-contract.md,确认理解
3. 一次只做一个 issue,完成后等下一个
4. 不要跨项目改动,不要改接口契约
5. 测试用 stub router / httpx.MockTransport,不能真调外部 API
6. Windows 优先兼容(pathlib.Path, --basetemp=.pytest-tmp)
7. 完成后用标准回报格式回复(见 CODEX_INSTRUCTIONS.md 末尾)

边界:
- 共享内核:000shared-llm-core 由我(人类)维护,你只能调用不能改
- 技术方案:tech-spec.md 是合同,改动需要新 issue
- 跨项目接口:任何破坏性变更 = blocking,要先讨论
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

每个 issue 单次 Codex 会话 ≤ 2 小时。超过 = 拆分。