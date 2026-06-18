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
MAX_RIS_PATH_HOPS = 1024
MAX_RIS_ANNOUNCEMENTS = 1024
MAX_RIS_PREFIXES = 4096


class RISMessageError(ValueError):
    """A type-hostile or over-large RIS Live message."""


def _as_dict(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise RISMessageError(f"{field} must be an object")
    return value


def _bounded_list(value: object, field: str, limit: int) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RISMessageError(f"{field} must be a list")
    if len(value) > limit:
        raise RISMessageError(f"{field} has {len(value)} entries, max {limit}")
    return value


def _asn(value: object, field: str) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        raise RISMessageError(f"{field} must be an ASN")
    try:
        asn = int(value)
    except (TypeError, ValueError) as err:
        raise RISMessageError(f"{field} must be an ASN") from err
    if asn < 0 or asn > 2**32 - 1:
        raise RISMessageError(f"{field} ASN out of range")
    return asn


def _string(value: object, field: str) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bool) or isinstance(value, (dict, list)):
        raise RISMessageError(f"{field} must be a scalar string")
    return str(value)


def _flatten_path(path: object) -> list[int]:
    """Flatten a RIS Live AS path (which may nest AS_SETs as sub-lists)."""
    hops = _bounded_list(path, "data.path", MAX_RIS_PATH_HOPS)
    out: list[int] = []
    for hop in hops:
        if isinstance(hop, list):
            if len(hop) > MAX_RIS_PATH_HOPS:
                raise RISMessageError("data.path AS_SET too large")
            for asn in hop:
                out.append(_asn(asn, "data.path[]"))
        else:
            out.append(_asn(hop, "data.path[]"))
        if len(out) > MAX_RIS_PATH_HOPS:
            raise RISMessageError(f"data.path flattened length exceeds {MAX_RIS_PATH_HOPS}")
    return out


def parse_ris_message(obj: object) -> list[BGPRoute]:
    """Normalize one RIS Live message into zero or more announced routes."""
    try:
        return _parse_ris_message(obj)
    except (RISMessageError, TypeError, ValueError, KeyError) as err:
        _log.warning("skipping malformed RIS Live message", error=str(err))
        return []


def _parse_ris_message(obj: object) -> list[BGPRoute]:
    msg = _as_dict(obj, "message")
    if msg.get("type") != "ris_message":
        return []
    data = _as_dict(msg.get("data", {}), "data")
    if data.get("type") != "UPDATE":
        return []

    as_path = _flatten_path(data.get("path", []))
    peer_addr = _string(data.get("peer", ""), "data.peer")
    peer_asn = _asn(data.get("peer_asn"), "data.peer_asn")

    routes: list[BGPRoute] = []
    emitted = 0
    for ann in _bounded_list(
        data.get("announcements", []), "data.announcements", MAX_RIS_ANNOUNCEMENTS
    ):
        ann_obj = _as_dict(ann, "data.announcements[]")
        for prefix in _bounded_list(
            ann_obj.get("prefixes", []), "data.announcements[].prefixes", MAX_RIS_PREFIXES
        ):
            emitted += 1
            if emitted > MAX_RIS_PREFIXES:
                raise RISMessageError(
                    f"message has more than {MAX_RIS_PREFIXES} announced prefixes"
                )
            routes.append(
                BGPRoute(
                    prefix=_string(prefix, "data.announcements[].prefixes[]"),
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
