"""Test double for ``shared_llm_core.router`` (v0.1 contract).

Only the subset consumed by 001AI-SOC-Agent is reproduced. See
``tests/_contract_stub/README.md`` before touching anything here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TaskTier(Enum):
    """Cost/capability tier requested from the router."""

    CHEAP = "cheap"
    STANDARD = "standard"
    PREMIUM = "premium"


@dataclass(frozen=True)
class ChatMessage:
    """One chat turn."""

    role: str
    content: str


@dataclass(frozen=True)
class ChatRequest:
    """Provider-agnostic chat completion request."""

    messages: list[ChatMessage]
    temperature: float = 0.7
    max_tokens: int | None = None
    response_format: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ChatChoice:
    """One completion candidate."""

    index: int
    message: ChatMessage
    finish_reason: str


@dataclass(frozen=True)
class ChatUsage:
    """Token accounting for one call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class ChatResponse:
    """Provider-agnostic chat completion response."""

    id: str
    model: str
    created: int
    choices: list[ChatChoice]
    usage: ChatUsage


class LLMRouter:
    """Tier-routing LLM client.

    The stub deliberately refuses to talk to a provider: any test that reaches
    a live ``chat()`` is a test that should have injected ``stub_router``.
    """

    @classmethod
    def from_env(cls) -> "LLMRouter":
        """Build a router from ``LLM_*`` environment variables."""
        return cls()

    def __enter__(self) -> "LLMRouter":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def chat(self, tier: TaskTier, request: ChatRequest) -> ChatResponse:
        """Raise: the contract stub has no provider behind it."""
        raise RuntimeError(
            "shared_llm_core contract stub cannot reach a provider; "
            "inject the stub_router fixture instead"
        )
