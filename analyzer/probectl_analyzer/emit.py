"""Event sinks for ``probectl.bgp.events``.

The default sink writes JSON Lines to a stream (stdout in production), which the
Go ``internal/bgp`` bridge tails and republishes onto the bus. A Kafka sink is a
future addition; the JSONL contract keeps the analyzer dependency-light and the
two sides decoupled by a stable schema.
"""

from __future__ import annotations

from typing import Protocol, TextIO

from .events import BGPEvent


class EventSink(Protocol):
    def emit(self, event: BGPEvent) -> None: ...


class JsonlSink:
    """Write one JSON event per line to a text stream."""

    def __init__(self, stream: TextIO):
        self._stream = stream

    def emit(self, event: BGPEvent) -> None:
        self._stream.write(event.to_json())
        self._stream.write("\n")
        self._stream.flush()


class ListSink:
    """Collect events in memory (tests)."""

    def __init__(self) -> None:
        self.events: list[BGPEvent] = []

    def emit(self, event: BGPEvent) -> None:
        self.events.append(event)
