"""RIPE RIS Live ingestion.

RIS Live streams BGP updates as JSON over a long-lived websocket. The parsing
core (:func:`parse_ris_message`, :func:`iter_updates`) is transport-agnostic so a
recorded capture can be replayed in tests; :class:`RISLiveClient` is the thin
live adapter that owns the websocket and its reconnect/backoff loop (S14 watch-out
— RIS Live is long-lived; handle reconnects).
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Iterator

from .log import get_logger
from .mrt import BGPRoute

_log = get_logger("probectl.analyzer.rislive")

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/"


def _flatten_path(path: list) -> list[int]:
    """Flatten a RIS Live AS path (which may nest AS_SETs as sub-lists)."""
    out: list[int] = []
    for hop in path:
        if isinstance(hop, list):
            out.extend(int(a) for a in hop)
        else:
            out.append(int(hop))
    return out


def parse_ris_message(obj: dict) -> list[BGPRoute]:
    """Normalize one RIS Live message into zero or more announced routes."""
    if obj.get("type") != "ris_message":
        return []
    data = obj.get("data", {})
    if data.get("type") != "UPDATE":
        return []

    as_path = _flatten_path(data.get("path", []))
    peer_addr = str(data.get("peer", ""))
    peer_asn = int(data["peer_asn"]) if data.get("peer_asn") else 0

    routes: list[BGPRoute] = []
    for ann in data.get("announcements", []):
        for prefix in ann.get("prefixes", []):
            routes.append(
                BGPRoute(
                    prefix=str(prefix),
                    as_path=list(as_path),
                    peer_asn=peer_asn,
                    peer_address=peer_addr,
                )
            )
    return routes


def iter_updates(messages: Iterable[str]) -> Iterator[BGPRoute]:
    """Yield routes from an iterable of RIS Live JSON message strings (a live
    socket or a recorded replay). Malformed lines are logged and skipped."""
    for raw in messages:
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as err:
            _log.warning("skipping malformed RIS Live message", error=str(err))
            continue
        yield from parse_ris_message(obj)


class RISLiveClient:
    """Live RIS Live websocket adapter with reconnect/backoff.

    ``websockets`` is an optional dependency; it is imported lazily so the parsing
    core stays usable (and testable) without it.
    """

    def __init__(
        self,
        url: str = RIS_LIVE_URL,
        host: str | None = None,
        prefixes: list[str] | None = None,
        max_backoff: float = 30.0,
    ):
        self._url = url
        self._host = host
        self._prefixes = prefixes or []
        self._max_backoff = max_backoff

    def _subscribe_messages(self) -> list[str]:
        host = {"host": self._host} if self._host else {}
        if self._prefixes:
            return [
                json.dumps(
                    {"type": "ris_subscribe", "data": {"type": "UPDATE", "prefix": p} | host}
                )
                for p in self._prefixes
            ]
        return [json.dumps({"type": "ris_subscribe", "data": {"type": "UPDATE"} | host})]

    def messages(self) -> Iterator[str]:
        """Yield raw JSON messages from the socket, reconnecting forever with
        exponential backoff. Requires the ``websockets`` package."""
        try:
            from websockets.sync.client import connect
        except ImportError as err:  # pragma: no cover - exercised only in live mode
            raise RuntimeError(
                "RIS Live live mode requires the 'websockets' package "
                "(pip install websockets); use --replay for recorded captures"
            ) from err

        backoff = 1.0
        while True:
            try:
                with connect(self._url) as ws:
                    for sub in self._subscribe_messages():
                        ws.send(sub)
                    backoff = 1.0
                    _log.info("RIS Live connected", url=self._url)
                    for message in ws:
                        yield message if isinstance(message, str) else message.decode()
            except Exception as err:  # noqa: BLE001 - reconnect on any socket error
                _log.warning("RIS Live disconnected; backing off", error=str(err), backoff=backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, self._max_backoff)

    def routes(self) -> Iterator[BGPRoute]:
        return iter_updates(self.messages())
