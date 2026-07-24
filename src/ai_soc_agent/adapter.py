"""001 SOC product adapter for v0.5 IntegrationGateway."""

from __future__ import annotations

from typing import Any, AsyncIterator

from shared_llm_core.finding import Finding, FindingSource
from shared_llm_core.gateway import ProductAdapter


class SOCProductAdapter(ProductAdapter):
    """Expose the existing SOC detection pipeline as an in-process adapter."""

    source = FindingSource.SOC

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        """Run the existing CLI scan pipeline and yield normalized Findings."""
        from ai_soc_agent.cli import scan_payload

        envelope = scan_payload(payload)
        events = payload.get("events", [])
        input_evidence = (
            tuple(str(event) for event in events) if isinstance(events, list) else ()
        )

        for item in envelope["findings"]:
            existing_evidence = item.get("evidence", [])
            normalized = {
                **item,
                "source": self.source.value,
                "evidence": [*existing_evidence, *input_evidence],
            }
            yield Finding.from_dict(normalized)

    def health(self) -> dict[str, Any]:
        """Return the product status exposed by IntegrationGateway health."""
        return {
            "status": "ok",
            "product": "001-soc",
            "version": "0.5.0",
        }
