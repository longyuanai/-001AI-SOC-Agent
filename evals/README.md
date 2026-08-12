# SOC LLM golden set

Baseline recorded: **2026-08-12**. Model identifier: **synthetic-replay-v1**.

The eight reviewed fixtures cover brute force, credential stuffing, lateral
movement, privilege escalation, geographic anomaly, an empty batch, a single
event, and `max_batch` truncation. They contain only synthetic labels and
recorded structured responses; replay mode sends no request to an LLM.

To run the deterministic gate from this repository:

```powershell
$env:SHARED_LLM_EVAL_MODE = "replay"
python -m pytest tests/test_eval_gate.py -q
```

For a reviewed live comparison, construct the same synthetic `EvalCase`
inputs, set `SHARED_LLM_EVAL_MODE=live`, and pass `run_eval` a callback that
invokes `analyze_events` through `LLMRouter`. Review deviations before replacing
a fixture; never record provider headers, keys, real hosts, addresses, users,
or customer events.
