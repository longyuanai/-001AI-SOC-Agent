"""SYSLOG-001 bounded UDP receiver tests."""

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from ai_soc_agent.config import DetectionConfig
from ai_soc_agent.correlator import correlate
from ai_soc_agent.ingest import SyslogUDPReceiver, parse_syslog_message
from ai_soc_agent.state import WindowStateStore

LINE = (
    "Jul 29 12:00:00 host sshd[1234]: Failed password for root "
    "from 203.0.113.9 port 50000 ssh2"
)


def test_parse_syslog_message_accepts_rfc3164_priority() -> None:
    event = parse_syslog_message(f"<34>{LINE}")

    assert event is not None
    assert event.actor == "203.0.113.9"
    assert event.result == "failure"


def test_parse_syslog_message_rejects_invalid_priority() -> None:
    assert parse_syslog_message(f"<999>{LINE}") is None


def test_parse_syslog_message_rejects_unrecognized_data() -> None:
    assert parse_syslog_message("not an sshd security event") is None


def test_receiver_rejects_non_positive_bounds() -> None:
    with pytest.raises(ValueError, match="queue_size"):
        SyslogUDPReceiver(lambda _event: None, queue_size=0)
    with pytest.raises(ValueError, match="max_datagram_bytes"):
        SyslogUDPReceiver(lambda _event: None, max_datagram_bytes=0)


def test_receiver_queue_is_bounded_and_counts_drops() -> None:
    receiver = SyslogUDPReceiver(lambda _event: None, queue_size=1)

    receiver.datagram_received(LINE.encode(), ("127.0.0.1", 1000))
    receiver.datagram_received(LINE.encode(), ("127.0.0.1", 1001))

    assert receiver.stats.received == 2
    assert receiver.stats.dropped == 1
    assert receiver.health()["queue_depth"] == 1
    assert receiver.health()["queue_capacity"] == 1


def test_receiver_rejects_invalid_utf8_and_oversized_packets() -> None:
    receiver = SyslogUDPReceiver(
        lambda _event: None,
        max_datagram_bytes=4,
    )

    receiver.datagram_received(b"\xff", ("127.0.0.1", 1000))
    receiver.datagram_received(b"12345", ("127.0.0.1", 1000))

    assert receiver.stats.parse_errors == 1
    assert receiver.stats.oversized == 1


def test_receiver_dispatches_sync_handler() -> None:
    async def exercise() -> None:
        events = []
        receiver = SyslogUDPReceiver(events.append)
        await receiver.start(port=0)
        receiver.datagram_received(LINE.encode(), ("127.0.0.1", 1000))
        await receiver.drain()
        await receiver.close()

        assert len(events) == 1
        assert receiver.stats.accepted == 1

    asyncio.run(exercise())


def test_receiver_dispatches_async_handler() -> None:
    async def exercise() -> None:
        actors: list[str] = []

        async def handle(event) -> None:
            await asyncio.sleep(0)
            actors.append(event.actor)

        receiver = SyslogUDPReceiver(handle)
        await receiver.start(port=0)
        receiver.datagram_received(LINE.encode(), ("127.0.0.1", 1000))
        await receiver.drain()
        await receiver.close()

        assert actors == ["203.0.113.9"]

    asyncio.run(exercise())


def test_receiver_isolates_parser_and_handler_errors() -> None:
    async def exercise() -> None:
        def bad_parser(_message: str):
            raise RuntimeError("bad parser")

        def bad_handler(_event) -> None:
            raise RuntimeError("bad handler")

        parser_receiver = SyslogUDPReceiver(lambda _event: None, parser=bad_parser)
        await parser_receiver.start(port=0)
        parser_receiver.datagram_received(b"message", ("127.0.0.1", 1000))
        await parser_receiver.drain()
        await parser_receiver.close()

        handler_receiver = SyslogUDPReceiver(bad_handler)
        await handler_receiver.start(port=0)
        handler_receiver.datagram_received(LINE.encode(), ("127.0.0.1", 1000))
        await handler_receiver.drain()
        await handler_receiver.close()

        assert parser_receiver.stats.parse_errors == 1
        assert handler_receiver.stats.handler_errors == 1
        assert handler_receiver.stats.accepted == 0

    asyncio.run(exercise())


def test_receiver_close_is_idempotent_and_stops_health() -> None:
    async def exercise() -> None:
        receiver = SyslogUDPReceiver(lambda _event: None)
        await receiver.start(port=0)
        assert receiver.health()["status"] == "ok"
        await receiver.close()
        await receiver.close()
        assert receiver.health()["status"] == "stopped"

    asyncio.run(exercise())


def test_real_udp_packets_trigger_stream_correlation() -> None:
    async def exercise() -> None:
        state = WindowStateStore(horizon=timedelta(minutes=5))
        alerts = []
        settings = DetectionConfig(
            brute_force_threshold=3,
            brute_force_window_seconds=60,
        )

        def handle(event) -> None:
            state.append([event])
            alerts[:] = correlate(state.snapshot(), config=settings)

        receiver = SyslogUDPReceiver(handle)
        host, port = await receiver.start(port=0)
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(host, port),
        )
        try:
            for second in range(3):
                line = LINE.replace("12:00:00", f"12:00:0{second}")
                transport.sendto(f"<34>{line}".encode())
            for _ in range(100):
                if receiver.stats.received == 3:
                    break
                await asyncio.sleep(0.01)
            await receiver.drain()
        finally:
            transport.close()
            await receiver.close()

        assert receiver.stats.accepted == 3
        assert len(alerts) == 1
        assert alerts[0].kind == "brute_force"

    asyncio.run(exercise())
