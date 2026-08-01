# AI-SOC-Agent

> AI log-analysis copilot for SOC analysts — Stage-1 happy path.
> First project of the **longyuanai AI Security Agent suite**.

Current maturity: **v0.7 engineering beta / controlled internal pilot only**.
It is not yet approved for an enterprise production SLA or multi-tenant SaaS.
See [Commercial readiness](docs/COMMERCIAL-READINESS.md) for the target
architecture, SLOs, threat model, delivery gates, and ordered implementation backlog.

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

The suite also runs without the sibling `000shared-llm-core` checkout — when
that package is missing, `tests/conftest.py` falls back to the contract stub in
`tests/_contract_stub/` and warns. Cross-repo tests skip themselves. See
`tests/_contract_stub/README.md` for what that does and does not cover.

## API server

Run the webhook API locally:

```bash
python -m ai_soc_agent.server
curl -H "Content-Type: application/json" \
  --data-binary @samples/multi_source_demo.log \
  http://127.0.0.1:8080/ingest
curl http://127.0.0.1:8080/alerts
curl http://127.0.0.1:8080/health
```

The server binds `127.0.0.1` by default. Before exposing it, set
`SOC_API_TOKEN` — `/ingest` accepts unauthenticated writes when it is unset,
and `main()` warns on startup if it is.

```bash
export SOC_API_TOKEN=...           # require: Authorization: Bearer <token>
export SOC_HOST=0.0.0.0            # bind elsewhere (default 127.0.0.1)
curl -H "Authorization: Bearer $SOC_API_TOKEN" ... http://127.0.0.1:8080/ingest
```

`GET /alerts` supports `type`, `severity`, `limit`, and `offset`, and returns
alerts newest-first with a `total` alongside the page `count`.

## Detection tuning

Thresholds live in `ai_soc_agent.config` and are overridable per deployment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `SOC_BRUTE_FORCE_THRESHOLD` | 5 batch / 10 stream | failures before an alert |
| `SOC_BRUTE_FORCE_WINDOW_SECONDS` | 60 batch / 300 stream | burst window |
| `SOC_CREDENTIAL_STUFFING_WINDOW_SECONDS` | 600 | cross-source window |
| `SOC_SUPPRESS_ACTORS` | _empty_ | comma-separated IPs/users to allowlist |
| `SOC_SUPPRESS_NETWORKS` | _empty_ | comma-separated CIDRs to allowlist |
| `SOC_LOG_LEVEL` | `INFO` | server log level |
| `SOC_ALERT_DB` | _empty_ | optional SQLite path for bounded normalized alerts |

Batch mode (CLI and gateway adapter) is tuned for "scan this log file"; stream
mode (`/ingest`) matches the correlation rule in `docs/tech-spec.md` §1 — 10
failures from one IP in 5 minutes. Use the suppression lists for vulnerability
scanners, monitoring probes, and jump hosts, which otherwise generate exactly
the traffic these rules look for.

## Detection rule manifests

The five built-in MITRE ATT&CK rules expose read-only, Sigma-compatible
metadata without changing the frozen `Rule.evaluate()` execution contract.
List or audit them locally:

```bash
python -m ai_soc_agent rules list
python -m ai_soc_agent rules list --json
python -m ai_soc_agent rules validate
```

The manifest records each rule's ID, log sources, MITRE tactic and technique,
severity, grouping dimensions, windows, required fields, and package entry
point. Validation detects metadata drift and confirms that every entry point
resolves to the registered executable rule. It never loads external rules or
calls a network service.

## Canonical detection fields

Before `RuleEngine` evaluation, `FieldMappingPipeline` adds deterministic
aliases to `NormalizedEvent.extra`:

- `src_ip`, `user`, `host`, `destination_host`, and `service`
- `process` for Windows process names
- `http_method` / `http_status` for Nginx
- `application` for Okta SSO targets

Explicit upstream canonical values win, unknown vendor fields remain intact,
and the operation is idempotent. The mapper does not perform network
enrichment and never invents `continent` or credential fingerprint fields.

## Upstream Geo enrichment

Geo anomaly detection accepts continent metadata from an upstream SIEM or log
shipper. `UpstreamGeoEnricher` recognizes canonical, dotted, and common nested
fields, then normalizes names and codes to `AF/AN/AS/EU/NA/OC/SA`.

Missing and invalid values receive an auditable `geo_enrichment_status`.
Invalid canonical values are excluded from detection, so arbitrary strings
cannot create a false cross-continent alert. This repository does not download
a GeoIP database or make a network request.

## Credential fingerprint enrichment

Credential-stuffing correlation accepts only upstream fingerprints formatted
as `hmac-sha256:<scope>:<64-hex>`. The scope isolates tenants or security
domains; identical digests from different scopes do not correlate.

Legacy hashes, short values, and plaintext-like input are removed from the
detection copy without retaining their value. Finding evidence is rendered as
`[credential redacted]`. AI-SOC-Agent never receives a plaintext password and
does not derive password hashes itself.

## Bounded stream state

Continuous `/ingest` correlation uses `WindowStateStore` to retain events
across webhook requests. The store:

- orders by event time and accepts bounded out-of-order input
- ignores exact duplicate events
- evicts history outside the 24-hour rule horizon
- enforces a global event-capacity limit
- supports isolated namespaces and an injected clock for deterministic tests

Each FastAPI app owns its store. CLI scans and `SOCProductAdapter.scan()` remain
pure batch operations with no hidden process-global history.

## Real-time syslog (v0.7)

The minimal live path receives RFC 3164 OpenSSH messages over UDP. It binds
localhost on unprivileged port 1514 by default, uses a bounded in-memory queue,
isolates malformed datagrams, and reports accepted/dropped/error counters when
it stops:

```bash
python -m ai_soc_agent syslog --host 127.0.0.1 --port 1514 --json
```

Each detected incident is emitted as one JSON line using the existing
`{"findings":[...]}` envelope. Startup and shutdown health messages go to
stderr, so stdout remains machine-readable. Exposing UDP beyond localhost
requires an explicit `--host` and appropriate host firewall controls. UDP has
no delivery guarantee; forwarders should retain their own retry/buffering
policy. Kafka, Redis Streams, RFC 5424 structured data, and privileged port 514
remain outside this minimal receiver.

## Finding deduplication

Every rule-generated Finding includes a stable `metadata.fingerprint` derived
from rule ID, correlation actor/host, and window start. The random Finding UUID
and frozen shared schema remain unchanged; evidence and credential-derived
values are never fingerprint inputs.

A long-running `SOCProductAdapter` suppresses repeated fingerprints for a
bounded five-minute cooldown. Its cache is capacity-limited and instance-local.
CLI scans deliberately bypass cross-call suppression and always return the
complete result for their submitted batch.

## Analyst feedback

The API records bounded human dispositions without changing rules online:

```bash
curl -H "Content-Type: application/json" \
  --data-binary '{"finding_id":"<id>","label":"true_positive","analyst":"alice"}' \
  http://127.0.0.1:8080/feedback
curl http://127.0.0.1:8080/feedback
```

Allowed labels are `true_positive`, `false_positive`, and `needs_review`.
Feedback writes use the same bearer-token policy as `/ingest`. Records support
filtering, pagination, and label summaries; they never update a threshold,
rule, or model automatically.

## Optional alert persistence

The webhook server remains memory-only by default. Set `SOC_ALERT_DB` to retain
the bounded normalized Alert store across restarts:

```bash
export SOC_ALERT_DB=/var/lib/ai-soc/alerts.db
python -m ai_soc_agent.server
```

The standard-library SQLite repository uses transactional upserts, enforces the
same `max_alerts` capacity as memory, removes malformed individual rows during
recovery, and closes through the FastAPI lifespan. It persists Alert fields
only—not raw events, credentials, tokens, or the cross-batch event window.
SQLite is intended for one AI-SOC-Agent process; multi-replica deployments
should continue exporting findings to the IntegrationGateway/SIEM registry.

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
│   ├── __init__.py        # public API
│   ├── config.py          # detection thresholds + suppression allowlists
│   ├── normalizer.py      # NormalizedEvent dataclass (UTC-normalized)
│   ├── field_mapping.py   # source fields → canonical detection aliases
│   ├── enrichment.py      # offline Geo + credential input validation
│   ├── state.py           # bounded cross-batch event-time state
│   ├── ingest.py          # bounded asyncio UDP syslog receiver
│   ├── dedup.py           # Finding fingerprint cooldown suppression
│   ├── feedback.py        # bounded human disposition records
│   ├── persistence.py     # optional bounded SQLite alert recovery
│   ├── parsers.py         # sshd / evtx / nginx / okta parsers
│   ├── patterns/          # MITRE ATT&CK rules on the v0.5 RuleEngine
│   │   ├── base.py        # SOCPattern + shared sliding-window helpers
│   │   ├── manifest.py    # auditable Sigma-compatible rule metadata
│   │   ├── brute_force.py         # T1110
│   │   ├── credential_stuffing.py # T1110.004
│   │   ├── geo_anomaly.py         # T1078
│   │   ├── lateral_movement.py    # T1021
│   │   └── priv_esc.py            # T1548
│   ├── correlator.py      # Alert compatibility layer over the RuleEngine
│   ├── findings.py        # v0.5 Finding construction
│   ├── adapter.py         # in-process IntegrationGateway adapter
│   ├── analyzer.py        # LLM triage (single-shot JSON)
│   ├── reporter.py        # Markdown report renderer
│   ├── server.py          # FastAPI /ingest, /alerts, /health
│   └── cli.py             # Click CLI: analyze | scan | rules
├── prompts/incident_triage/v1.yml
├── samples/               # ssh, nginx, okta, windows, mitre/
├── tests/
│   ├── _contract_stub/    # shared_llm_core stand-in for CI
│   └── integration/       # cross-repo, skipped without the siblings
└── pyproject.toml
```

## Next steps (out of PoC scope)

Commercial C1 starts with `SEC-AUTH-001`, then observability, detection-quality
evaluation, performance/soak testing, operations runbooks, and supply-chain
gates. RFC 5424/TCP/TLS, durable shared state, reliable delivery, HA, and
multi-tenant controls belong to later gates. See
[`docs/COMMERCIAL-READINESS.md`](docs/COMMERCIAL-READINESS.md); passing unit
tests alone does not make the service production-ready.
