"""Bounded asynchronous UDP syslog ingestion for v0.7."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any, Awaitable, Callable

from ai_soc_agent.normalizer import NormalizedEvent
from ai_soc_agent.parsers import parse_line

logger = logging.getLogger(__name__)

DEFAULT_SYSLOG_HOST = "127.0.0.1"
DEFAULT_SYSLOG_PORT = 1514
DEFAULT_SYSLOG_QUEUE_SIZE = 1_024
DEFAULT_MAX_DATAGRAM_BYTES = 65_507

_PRI_RE = re.compile(r"^<(?P<priority>\d{1,3})>")
_STOP = object()

EventHandler = Callable[[NormalizedEvent], Awaitable[None] | None]
SyslogParser = Callable[[str], NormalizedEvent | None]


def parse_syslog_message(message: str) -> NormalizedEvent | None:
    """Parse one RFC 3164-style sshd message, with an optional PRI prefix."""
    line = message.strip("\x00\r\n")
    if not line:
        return None
    match = _PRI_RE.match(line)
    if match is not None:
        if int(match.group("priority")) > 191:
            return None
        line = line[match.end() :]
    return parse_line(line)


@dataclass(frozen=True, slots=True)
class SyslogStats:
    """Immutable accounting snapshot for one receiver."""

    received: int = 0
    accepted: int = 0
    parse_errors: int = 0
    dropped: int = 0
    oversized: int = 0
    handler_errors: int = 0
    transport_errors: int = 0


class SyslogUDPReceiver(asyncio.DatagramProtocol):
    """Receive, queue, parse, and dispatch UDP syslog without unbounded state."""

    def __init__(
        self,
        on_event: EventHandler,
        *,
        parser: SyslogParser = parse_syslog_message,
        queue_size: int = DEFAULT_SYSLOG_QUEUE_SIZE,
        max_datagram_bytes: int = DEFAULT_MAX_DATAGRAM_BYTES,
    ) -> None:
        if queue_size <= 0:
            raise ValueError("queue_size must be positive")
        if max_datagram_bytes <= 0:
            raise ValueError("max_datagram_bytes must be positive")
        self._on_event = on_event
        self._parser = parser
        self._queue: asyncio.Queue[tuple[str, Any] | object] = asyncio.Queue(
            maxsize=queue_size
        )
        self._max_datagram_bytes = max_datagram_bytes
        self._transport: asyncio.DatagramTransport | None = None
        self._worker: asyncio.Task[None] | None = None
        self._accepting = True
        self._closed = False
        self._counters = {field: 0 for field in SyslogStats.__dataclass_fields__}

    @property
    def address(self) -> tuple[str, int] | None:
        """Return the bound IPv4 address after :meth:`start`."""
        if self._transport is None:
            return None
        value = self._transport.get_extra_info("sockname")
        if isinstance(value, tuple) and len(value) >= 2:
            return str(value[0]), int(value[1])
        return None

    @property
    def stats(self) -> SyslogStats:
        """Return an immutable metrics snapshot."""
        return SyslogStats(**self._counters)

    async def start(
        self,
        *,
        host: str = DEFAULT_SYSLOG_HOST,
        port: int = DEFAULT_SYSLOG_PORT,
    ) -> tuple[str, int]:
        """Bind the UDP endpoint and start the single bounded consumer."""
        if self._worker is not None or self._closed:
            raise RuntimeError("receiver has already been started or closed")
        if not 0 <= port <= 65_535:
            raise ValueError("port must be between 0 and 65535")
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self,
            local_addr=(host, port),
        )
        self._transport = transport
        self._worker = asyncio.create_task(self._consume(), name="soc-syslog-consumer")
        address = self.address
        if address is None:  # pragma: no cover - event loop contract guard
            await self.close()
            raise RuntimeError("syslog transport did not expose a socket address")
        return address

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self._increment("received")
        if not self._accepting:
            self._increment("dropped")
            return
        if len(data) > self._max_datagram_bytes:
            self._increment("oversized")
            return
        try:
            message = data.decode("utf-8")
        except UnicodeDecodeError:
            self._increment("parse_errors")
            return
        try:
            self._queue.put_nowait((message, addr))
        except asyncio.QueueFull:
            self._increment("dropped")

    def error_received(self, exc: Exception) -> None:
        self._increment("transport_errors")
        logger.warning("syslog UDP transport error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            self._increment("transport_errors")
            logger.warning("syslog UDP connection lost: %s", exc)

    async def drain(self) -> None:
        """Wait until every currently queued datagram has been handled."""
        await self._queue.join()

    async def close(self) -> None:
        """Stop accepting packets and drain the queue before returning."""
        if self._closed:
            return
        self._accepting = False
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._worker is not None:
            await self._queue.join()
            await self._queue.put(_STOP)
            await self._worker
            self._worker = None
        self._closed = True

    def health(self) -> dict[str, Any]:
        """Return bounded-queue state suitable for a health endpoint."""
        return {
            "status": "stopped" if self._closed else "ok",
            "product": "001-soc-syslog",
            "address": self.address,
            "queue_depth": self._queue.qsize(),
            "queue_capacity": self._queue.maxsize,
            **asdict(self.stats),
        }

    async def _consume(self) -> None:
        while True:
            item = await self._queue.get()
            try:
                if item is _STOP:
                    return
                message, _addr = item
                try:
                    event = self._parser(message)
                except Exception:
                    self._increment("parse_errors")
                    logger.exception("syslog parser failed")
                    continue
                if event is None:
                    self._increment("parse_errors")
                    continue
                try:
                    result = self._on_event(event)
                    if inspect.isawaitable(result):
                        await result
                except Exception:
                    self._increment("handler_errors")
                    logger.exception("syslog event handler failed")
                    continue
                self._increment("accepted")
            finally:
                self._queue.task_done()

    def _increment(self, name: str) -> None:
        self._counters[name] += 1


__all__ = [
    "DEFAULT_MAX_DATAGRAM_BYTES",
    "DEFAULT_SYSLOG_HOST",
    "DEFAULT_SYSLOG_PORT",
    "DEFAULT_SYSLOG_QUEUE_SIZE",
    "SyslogStats",
    "SyslogUDPReceiver",
    "parse_syslog_message",
]
