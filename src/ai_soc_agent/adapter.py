"""001 SOC product adapter for v0.5 IntegrationGateway."""

from __future__ import annotations

from typing import Any, AsyncIterator

from shared_llm_core.finding import Finding, FindingSource
from shared_llm_core.gateway import ProductAdapter

from ai_soc_agent.dedup import FindingDeduplicator

#: v0.5 IntegrationGateway contract implemented by this adapter.
GATEWAY_CONTRACT_VERSION = "0.5.0"


class SOCProductAdapter(ProductAdapter):
    """Expose the existing SOC detection pipeline as an in-process adapter."""

    source = FindingSource.SOC

    def __init__(
        self,
        *,
        deduplicator: FindingDeduplicator | None = None,
    ) -> None:
        self._deduplicator = (
            deduplicator if deduplicator is not None else FindingDeduplicator()
        )

    async def scan(self, payload: dict[str, Any]) -> AsyncIterator[Finding]:
        """Run the existing CLI scan pipeline and yield normalized Findings."""
        from ai_soc_agent.cli import scan_payload

        envelope = scan_payload(payload)
        # Each finding already carries the events that matched it; appending the
        # entire input batch to every finding made a 10k-event scan emit 10k
        # evidence strings per finding.
        for item in envelope["findings"]:
            finding = Finding.from_dict({**item, "source": self.source.value})
            if self._deduplicator.accept(finding).accepted:
                yield finding

    def health(self) -> dict[str, Any]:
        """Return the product status exposed by IntegrationGateway health."""
        return {
            "status": "ok",
            "product": "001-soc",
            # The gateway contract version this adapter implements, which is
            # deliberately not the package version (see __init__.__version__).
            "version": GATEWAY_CONTRACT_VERSION,
        }
