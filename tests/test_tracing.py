from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from ai_soc_agent import cli


def test_scan_entrypoint_creates_span(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[tuple[str, dict[str, object]]] = []

    @contextmanager
    def recording_span(
        name: str,
        *,
        attributes: dict[str, object],
    ) -> Iterator[None]:
        captured.append((name, attributes))
        yield

    expected = {"findings": []}
    monkeypatch.setattr(cli, "span", recording_span)
    monkeypatch.setattr(cli, "_scan_payload", lambda _payload, **_kwargs: expected)

    assert cli.scan_payload({}, log_file="C:/private/customer.log") is expected
    assert captured == [
        (
            "product.scan",
            {"product.id": "001", "scan.target_type": "log_file"},
        )
    ]
