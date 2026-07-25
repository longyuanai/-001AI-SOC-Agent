"""Live subprocess tests for the shared IntegrationGateway SOC adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SUITE_ROOT = PROJECT_ROOT.parent
INTEGRATION_ROOT = SUITE_ROOT / "000shared-integration"
CORE_ROOT = SUITE_ROOT / "000shared-llm-core"
FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "sshd_bruteforce.log"
BASE_URL = "http://127.0.0.1:18080"

# These boot the real suite gateway from sibling repos. Skip when only this
# project is checked out instead of failing the whole run.
pytestmark = pytest.mark.skipif(
    not (INTEGRATION_ROOT.is_dir() and CORE_ROOT.is_dir()),
    reason="requires 000shared-integration and 000shared-llm-core checked out alongside",
)


def _request(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


@pytest.fixture(scope="module")
def gateway_server() -> Iterator[None]:
    env = os.environ.copy()
    python_paths = [
        str(INTEGRATION_ROOT / "src"),
        str(CORE_ROOT / "src"),
        str(PROJECT_ROOT / "src"),
    ]
    if current := env.get("PYTHONPATH"):
        python_paths.append(current)
    env["PYTHONPATH"] = os.pathsep.join(python_paths)

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "shared_integration.gateway:app",
            "--host",
            "127.0.0.1",
            "--port",
            "18080",
            "--log-level",
            "warning",
        ],
        cwd=INTEGRATION_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                pytest.fail(f"gateway exited early\nstdout: {stdout}\nstderr: {stderr}")
            try:
                _request("GET", "/v0.5/health")
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
            else:
                break
        else:
            pytest.fail("gateway did not become healthy within 15 seconds")
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def test_post_scan_returns_findings(gateway_server: None) -> None:
    events = [
        line
        for line in FIXTURE.read_text(encoding="utf-8").splitlines()
        if "Failed password" in line
    ]

    response = _request(
        "POST",
        "/v0.5/001/scan",
        {"source": "sshd", "events": events},
    )

    assert response["source"] == "001"
    assert response["count"] == 1
    assert response["findings"][0]["source"] == "001"
    assert response["findings"][0]["severity"] == "high"


def test_sshd_bruteforce_log_triggers_alert(gateway_server: None) -> None:
    response = _request(
        "POST",
        "/v0.5/001/scan",
        {"source": "sshd", "log_file": str(FIXTURE)},
    )

    assert response["count"] == 1
    assert response["findings"][0]["host"] == "203.0.113.45"
    assert response["findings"][0]["title"] == "Brute force from 203.0.113.45"


def test_health_endpoint_reports_soc_ok(gateway_server: None) -> None:
    response = _request("GET", "/v0.5/health")

    assert response["status"] == "ok"
    assert len(response["products"]) == 6
    assert response["products"]["001"]["status"] == "ok"
    assert response["products"]["001"]["available"] is True
