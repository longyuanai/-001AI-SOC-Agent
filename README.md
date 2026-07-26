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

`shared-llm-core` is a `path` dependency on `../000shared-llm-core`, so this
project cannot be installed from a standalone clone. Check both repos out side
by side under their common parent first:

```
003AI+网络安全/
├── 000shared-llm-core/       # required: path dependency
├── 000shared-integration/    # optional: enables the cross-repo suite tests
└── 001AI-SOC-Agent/          # this repo
```

```bash
cd 001AI-SOC-Agent
poetry install
```

CI does the same thing — see `.github/workflows/ci.yml`. If the sibling repos
live under different names, point the `SHARED_LLM_CORE_REPO` /
`SHARED_INTEGRATION_REPO` Actions variables at them (and add a
`SUITE_REPO_TOKEN` secret if they are private).

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
poetry run pytest -q
poetry run ruff check src tests
```

All tests use a stubbed router; no live LLM is required. Tests that need
`000shared-integration` skip themselves when it is not checked out, so a
partial checkout reports skips instead of collection errors.

## Detection profiles

Thresholds live in `src/ai_soc_agent/config.py`, and there are exactly two
profiles so the same log cannot silently score differently per entry point:

| Profile | Used by | Brute force |
|---------|---------|-------------|
| `detection_facts()` (default) | CLI `scan`, IntegrationGateway adapter | 5 failures / 60 s |
| `STREAMING_PROFILE` | `correlate()` behind `/ingest` | 10 failures / 300 s |

The streaming path sees a continuous firehose and deliberately runs the less
twitchy threshold. Per-request tuning goes in the payload
(`brute_force_threshold`), not in a new literal.

All five MITRE patterns (T1110, T1110.004, T1078, T1548, T1021) surface both as
v0.5 Findings and as `/alerts` entries. Each pattern reports one finding per
independent match, so three IPs brute-forcing at once yield three findings.

Login attempts are recognized per source: sshd `Failed`/`Accepted` for any auth
method (password, publickey, ...), Okta `user.session.start`, Windows 4624/4625,
and — for nginx — a credential-submitting verb (`POST`/`PUT`/`PATCH`) against an
auth path. `GET /login` is a form load, not an authentication attempt.

If your login route is not one of the built-in segments (`login`, `signin`,
`session`, `oauth`, `token`, ...), add it:

```bash
export AI_SOC_LOGIN_PATH_SEGMENTS="j_security_check,identity"
```

The additions apply on top of the defaults, never instead of them.

## API server

Run the webhook API locally. It binds `127.0.0.1` by default; override with
`AI_SOC_HOST` / `AI_SOC_PORT`.

```bash
python -m ai_soc_agent.server
curl -H "Content-Type: application/json" \
  --data-binary @samples/multi_source_demo.log \
  http://127.0.0.1:8080/ingest
curl http://127.0.0.1:8080/alerts
curl http://127.0.0.1:8080/health
```

**Authentication.** Set `AI_SOC_API_TOKEN` and `/ingest` and `/alerts` require
`Authorization: Bearer <token>`. Leave it unset only on a trusted loopback
interface — the server logs a warning at startup when it is missing. `/health`
is always unauthenticated so container probes keep working.

```bash
export AI_SOC_API_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
python -m ai_soc_agent.server
curl -H "Authorization: Bearer $AI_SOC_API_TOKEN" http://127.0.0.1:8080/alerts
```

`/ingest` keeps a bounded in-memory store and re-correlates only the window a
rule can still match (`config.MAX_RULE_WINDOW_SECONDS`), so cost does not grow
with uptime. Alert ids are derived from `(type, actor)`, so replaying the same
events updates one alert instead of creating duplicates.

The Docker build needs both this project and its sibling `000shared-llm-core`
path dependency. Run it from their common `003AI+网络安全` parent directory:

```bash
docker build -f 001AI-SOC-Agent/Dockerfile -t ai-soc-agent:0.1 .
docker run --rm -p 8080:8080 ai-soc-agent:0.1
```

## Called by IntegrationGateway

The shared gateway invokes this product through an isolated JSON subprocess.
The public adapter envelope deliberately omits `source`; `SOCAdapter` injects
the frozen `FindingSource.SOC` value (`"001"`) before registry insertion.

```bash
echo '{"source":"sshd","events":[]}' | \
  python -m ai_soc_agent.cli scan --json
# {"findings":[]}

python -m ai_soc_agent.cli scan \
  --log-file tests/fixtures/sshd_bruteforce.log --json

# Non-sshd input needs --log-type, or it is parsed as sshd and yields nothing.
python -m ai_soc_agent.cli scan \
  --log-file samples/nginx_login_bruteforce.log --log-type nginx
# 1 finding(s)
# - [high] Brute force from 203.0.113.77
```

Start the suite gateway from `000shared-integration`, then use the frozen
Finding source value in the route:

```bash
python -m shared_integration.gateway
curl http://127.0.0.1:8080/v0.5/health
curl -H "Content-Type: application/json" \
  --data-binary '{"source":"sshd","log_file":"E:/path/to/sshd_bruteforce.log"}' \
  http://127.0.0.1:8080/v0.5/001/scan
```

## Repo layout

```
001AI-SOC-Agent/
├── src/ai_soc_agent/
│   ├── __init__.py        # public API (LLM exports are lazy)
│   ├── config.py          # detection thresholds + profiles
│   ├── normalizer.py      # NormalizedEvent dataclass
│   ├── parsers.py         # sshd / evtx / nginx / okta parsers
│   ├── patterns/          # MITRE ATT&CK rules on the v0.5 RuleEngine
│   │   ├── base.py        # SOCPattern: windowing + Finding construction
│   │   ├── brute_force.py         # T1110
│   │   ├── credential_stuffing.py # T1110.004
│   │   ├── geo_anomaly.py         # T1078
│   │   ├── lateral_movement.py    # T1021
│   │   └── priv_esc.py            # T1548
│   ├── correlator.py      # rule engine entry point + Alert projection
│   ├── findings.py        # v0.5 Finding construction helpers
│   ├── adapter.py         # SOCProductAdapter for IntegrationGateway
│   ├── prompts.py         # loader for prompts/<task>/<version>.yml
│   ├── analyzer.py        # LLM triage (single-shot JSON)
│   ├── reporter.py        # Markdown report renderer
│   ├── server.py          # FastAPI /ingest, /alerts, /health
│   └── cli.py             # Click CLI: ai-soc scan | analyze
├── prompts/incident_triage/v1.yml   # the only copy of the triage prompt
├── samples/               # sshd, nginx, okta, windows + samples/mitre/
├── tests/
│   └── integration/       # needs the sibling suite repos; skips without them
├── .github/workflows/ci.yml
└── pyproject.toml
```

## Next steps (out of PoC scope)

See `docs/tech-spec.md` for the full v0.3 / v0.6 / v1.0 roadmap.
The PoC covers the Stage-1 happy path only; multi-step ReAct agents,
context aggregation, and protocol emulators land in v0.3.
