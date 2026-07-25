"""Test double for ``shared_llm_core``.

Only the subset consumed by 001AI-SOC-Agent is reproduced. See
``tests/_contract_stub/README.md`` before touching anything here.
"""

from shared_llm_core.router import (
    ChatChoice,
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ChatUsage,
    LLMRouter,
    TaskTier,
)

IS_CONTRACT_STUB = True

__all__ = [
    "ChatChoice",
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "ChatUsage",
    "IS_CONTRACT_STUB",
    "LLMRouter",
    "TaskTier",
]
