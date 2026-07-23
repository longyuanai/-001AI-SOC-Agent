# AI-SOC-Agent

> AI log-analysis copilot for SOC analysts — Stage-1 happy path.
> First project of the **longyuanai AI Security Agent suite**.

## What it does (PoC)

Parses an OpenSSH `auth.log` file, normalizes each line into a structured
event, sends a small batch to the LLM via `shared-llm-core`, and renders a
Markdown incident report.

```
auth.log ──► Parser ──► NormalizedEvent[*] ──► LLM Router (shared-llm-core)
                                                  │
                                                  ▼
                                          AlertAssessment (JSON)
                                                  │
                                                  ▼
                                       Markdown Incident Report
```

## Install

```bash
cd 001AI-SOC-Agent
poetry install
```

This pulls `shared-llm-core` from the sibling repo at
`../000shared-llm-core` via a `path` dependency.

## Run the demo

The CLI uses the same env vars / YAML config as `shared-llm-core`. Pick a
provider first:

```bash
# Local vLLM (Qwen2.5-7B-Instruct)
docker compose -f ../000shared-llm-core/docker-compose.yml up -d vllm
export LLM_PROVIDERS=local
ai-soc analyze -i samples/ssh_bruteforce.log -o report.md
```

```bash
# Claude via OpenAI-compatible proxy
export LLM_PROVIDERS=claude
export LLM_CLAUDE_BASE_URL=https://your-proxy/v1
export LLM_CLAUDE_API_KEY=sk-...
ai-soc analyze -i samples/ssh_bruteforce.log -o report.md
```

Without any provider configured, the CLI still parses and prints "no
recognizable events" — handy for CI smoke tests.

## Test

```bash
poetry run pytest -v
```

All tests use a stubbed router; no live LLM is required.

## API server

Run the webhook API locally:

```bash
python -m ai_soc_agent.server
curl -H "Content-Type: application/json" \
  --data-binary @samples/multi_source_demo.log \
  http://127.0.0.1:8080/ingest
curl http://127.0.0.1:8080/alerts
```

The Docker build needs both this project and its sibling `000shared-llm-core`
path dependency. Run it from their common `003AI+网络安全` parent directory:

```bash
docker build -f 001AI-SOC-Agent/Dockerfile -t ai-soc-agent:0.1 .
docker run --rm -p 8080:8080 ai-soc-agent:0.1
```

## Repo layout

```
001AI-SOC-Agent/
├── src/ai_soc_agent/
│   ├── __init__.py        # public API
│   ├── normalizer.py      # NormalizedEvent dataclass
│   ├── parsers.py         # OpenSSH auth.log parser
│   ├── analyzer.py        # LLM triage (single-shot JSON)
│   ├── reporter.py        # Markdown report renderer
│   └── cli.py             # Click CLI: ai-soc analyze
├── prompts/incident_triage/v1.yml
├── samples/ssh_bruteforce.log
├── tests/
└── pyproject.toml
```

## Next steps (out of PoC scope)

See `docs/tech-spec.md` for the full v0.3 / v0.6 / v1.0 roadmap.
The PoC covers the Stage-1 happy path only; multi-step ReAct agents,
context aggregation, and protocol emulators land in v0.3.
