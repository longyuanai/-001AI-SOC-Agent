"""Focused regressions for frozen Alert and CLI envelope behavior."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from ai_soc_agent.cli import scan_payload
from ai_soc_agent.correlator import correlate
from ai_soc_agent.normalizer import NormalizedEvent


def test_legacy_alert_correlation_still_emits_two_known_alerts() -> None:
    path = Path(__file__).parents[1] / "samples" / "multi_source_demo.log"
    payload = json.loads(path.read_text(encoding="utf-8"))
    events = [
        NormalizedEvent(
            ts=datetime.fromisoformat(item["ts"].replace("Z", "+00:00")),
            actor=item["actor"],
            action=item["action"],
            target=item["target"],
            result=item["result"],
            source=item["source"],
            extra=item["extra"],
        )
        for item in payload["events"]
    ]

    assert [alert.kind for alert in correlate(events)] == [
        "brute_force",
        "credential_stuffing",
    ]


def test_cli_empty_envelope_shape_remains_frozen() -> None:
    assert scan_payload({"source": "sshd", "events": []}) == {"findings": []}
