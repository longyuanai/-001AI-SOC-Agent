"""No-op telemetry seam for the standalone shared-core contract stub."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager


@contextmanager
def span(
    _name: str,
    *,
    attributes: Mapping[str, object] | None = None,
) -> Iterator[None]:
    del attributes
    yield


__all__ = ["span"]
