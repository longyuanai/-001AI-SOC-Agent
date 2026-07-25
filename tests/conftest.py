"""Shared pytest fixtures for AI-SOC-Agent tests.

Per the v0.1 contract (`000shared-llm-core/docs/v0.1-contract.md` §5), every
downstream project must expose a ``stub_router`` fixture in ``conftest.py``
so that integration tests can stand in for ``shared_llm_core.LLMRouter`` without
hitting a real provider.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest


def _ensure_shared_llm_core() -> None:
    """Fall back to the contract stub when the sibling repo isn't checked out.

    ``pyproject.toml`` declares ``shared-llm-core`` as a ``path`` dependency on
    ``../000shared-llm-core``. Without that sibling directory the whole suite is
    uncollectable, which is why this repo had no CI. Prefer the real package;
    only stand in for it when it is genuinely absent.
    """
    if importlib.util.find_spec("shared_llm_core") is not None:
        return
    stub_root = Path(__file__).parent / "_contract_stub"
    sys.path.insert(0, str(stub_root))
    warnings.warn(
        "shared_llm_core not installed; using tests/_contract_stub. Cross-repo "
        "behavior is NOT covered — see tests/_contract_stub/README.md.",
        stacklevel=2,
    )


_ensure_shared_llm_core()

from shared_llm_core import (  # noqa: E402
    ChatChoice,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ChatUsage,
)


@dataclass
class StubRouter:
    """Minimal in-memory replacement for ``shared_llm_core.LLMRouter``.

    Records every ``chat()`` invocation and returns a fixed ``ChatResponse``
    whose message content is ``json.dumps(reply)``. Tests may swap the
    ``reply`` dict between calls (e.g. via ``stub_router.set_reply``) or
    inspect ``stub_router.calls`` for assertions on the outgoing request.
    """

    reply: dict = field(default_factory=dict)
    calls: list[ChatRequest] = field(default_factory=list)
    _call_index: int = 0

    def chat(self, tier: Any, req: ChatRequest) -> ChatResponse:  # noqa: ARG002
        """Return a deterministic response and remember the request."""
        self.calls.append(req)
        # Allow per-call reply overrides via a side-channel on the request.
        per_call = getattr(req, "metadata", None) or {}
        override = per_call.get("__stub_reply_override__")
        body = override if override is not None else self._reply_for(self._call_index)
        self._call_index += 1
        return ChatResponse(
            id="stub",
            model="stub",
            created=0,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=json.dumps(body)),
                    finish_reason="stop",
                )
            ],
            usage=ChatUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30),
        )

    def _reply_for(self, index: int) -> dict:
        """Default reply strategy: single dict for the lifetime of the stub.

        Tests that need different replies per call can attach a list via
        ``StubRouter(replies=[...])`` and we will pop them in order.
        """
        return self.reply

    def set_reply(self, reply: dict) -> None:
        """Replace the reply payload used for subsequent calls."""
        self.reply = reply
        self._call_index = 0


@pytest.fixture
def stub_router() -> StubRouter:
    """Module-level fixture: a fresh StubRouter per test."""
    return StubRouter(reply={})


@pytest.fixture
def stub_router_with():
    """Factory fixture: ``stub_router_with(reply)`` returns a configured stub.

    Usage::

        def test_x(stub_router_with):
            router = stub_router_with({"severity": "high"})
            ...
    """

    def _make(reply: dict | None = None) -> StubRouter:
        return StubRouter(reply=reply or {})

    return _make