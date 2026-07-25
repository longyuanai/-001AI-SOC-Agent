"""Test double for ``shared_llm_core.gateway`` (v0.5 IntegrationGateway).

Only the subset consumed by 001AI-SOC-Agent is reproduced. See
``tests/_contract_stub/README.md`` before touching anything here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator

from shared_llm_core.finding import Finding, FindingSource


class ProductAdapter(ABC):
    """In-process contract every suite product exposes to the gateway."""

    source: FindingSource

    @abstractmethod
    def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        """Yield Findings for one gateway scan request."""

    @abstractmethod
    def health(self) -> dict[str, Any]:
        """Return this product's status for the gateway health route."""
