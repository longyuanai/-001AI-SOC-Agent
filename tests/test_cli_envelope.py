"""IntegrationGateway JSON-envelope contract tests."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from ai_soc_agent.cli import cli

SUITE_ROOT = Path(__file__).resolve().parents[2]
INTEGRATION_SRC = SUITE_ROOT / "000shared-integration" / "src"
if INTEGRATION_SRC.is_dir() and str(INTEGRATION_SRC) not in sys.path:
    sys.path.insert(0, str(INTEGRATION_SRC))

try:
    from shared_integration.adapters.soc import SOCAdapter
except ImportError:  # sibling repo not checked out (CI, clean container)
    SOCAdapter = None


def _failed_lines(count: int = 5, ip: str = "203.0.113.45") -> list[str]:
    return [
        (
            f"Jul 24 01:00:{index:02d} soc-host sshd[{1200 + index}]: "
            f"Failed password for root from {ip} port {51000 + index} ssh2"
        )
        for index in range(count)
    ]


def test_scan_sshd_returns_envelope() -> None:
    payload = {"source": "sshd", "events": []}

    result = CliRunner().invoke(cli, ["scan", "--input", json.dumps(payload), "--json"])

    assert result.exit_code == 0
    assert json.loads(result.output) == {"findings": []}


def test_scan_with_existing_detect_rule() -> None:
    payload = {
        "source": "sshd",
        "events": _failed_lines(10),
        "brute_force_threshold": 10,
    }

    result = CliRunner().invoke(cli, ["scan", "--input", json.dumps(payload), "--json"])

    assert result.exit_code == 0
    envelope = json.loads(result.output)
    assert len(envelope["findings"]) == 1
    finding = envelope["findings"][0]
    assert finding["severity"] == "high"
    assert finding["confidence"] == 0.92
    assert finding["host"] == "203.0.113.45"
    assert "source" not in finding


def test_cli_handles_bad_json_gracefully() -> None:
    result = CliRunner().invoke(cli, ["scan", "--input", "{bad-json", "--json"])

    assert result.exit_code != 0
    assert "invalid JSON payload" in result.output


@pytest.mark.cross_repo
@pytest.mark.skipif(SOCAdapter is None, reason="000shared-integration not checked out")
def test_json_subprocess_adapter_runs_soc_cli_end_to_end() -> None:
    async def collect() -> list:
        adapter = SOCAdapter(SUITE_ROOT / "001AI-SOC-Agent")
        return [
            finding
            async for finding in adapter.scan(
                {"source": "sshd", "events": _failed_lines()}
            )
        ]

    findings = asyncio.run(collect())

    assert len(findings) == 1
    assert findings[0].source.value == "001"
    assert findings[0].severity.value == "high"
    assert findings[0].host == "203.0.113.45"
