# `tests/_contract_stub/` · shared-llm-core 契约替身

**这不是 `000shared-llm-core`。** 这是一个仅供测试使用的最小替身，用来让本仓库
在没有兄弟仓库 checkout 的环境里（CI、干净容器、新同事的机器）也能跑 `pytest`。

## 为什么需要它

`pyproject.toml` 用 `path = "../000shared-llm-core"` 声明依赖。一旦没有那个同级
目录，`import shared_llm_core` 直接失败，**整个测试套件一条都跑不了** —— 这正是
本仓库长期没有 CI 的根因。

## 加载规则

`tests/conftest.py` 只在**真包导入失败时**才把本目录插入 `sys.path`，并打印一条
警告。真包存在时本目录完全不参与。所以：

- 本地/生产（有 `000shared-llm-core`）→ 用真包，替身休眠
- CI/干净容器 → 用替身，测试仍可运行

## 边界

替身只实现被本仓库实际使用到的接口子集，行为按 v0.5 冻结契约复刻。它**不能**替代
真包做集成验证：跨仓库的端到端行为仍必须在装有 `000shared-llm-core` +
`000shared-integration` 的环境里跑（见 `tests/integration/`，缺仓库时自动 skip）。

改动 Finding / RuleEngine 契约时，**先改真包**，再同步本替身。
