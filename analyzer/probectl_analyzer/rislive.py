# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

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

from .as_path import AS_SEQUENCE, AS_SET, ASPathSegment
from .config import DEFAULT_RIS_MEMORY_BYTES
from .log import get_logger
from .mrt import BGPRoute

_log = get_logger("probectl.analyzer.rislive")

RIS_LIVE_URL = "wss://ris-live.ripe.net/v1/ws/"
# Complete source paths follow finite whole-message workspace admission, not
# an independent hop ceiling. Includes retained segments and per-prefix copies.
MAX_RIS_ANNOUNCEMENTS = 1024
MAX_RIS_PREFIXES = 4096
# A RIS collector name is "rrcNN.ripe.net"; anything longer is hostile input.
MAX_RIS_HOST_LENGTH = 253


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
    if isinstance(value, bool) or not isinstance(value, (int, str)):
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


def _timestamp_unix_nano(value: object, field: str) -> int:
    if value in (None, ""):
        return 0
    if isinstance(value, bool) or isinstance(value, (dict, list)):
        raise RISMessageError(f"{field} must be a unix timestamp")
    try:
        ts = float(value)
    except (TypeError, ValueError) as err:
        raise RISMessageError(f"{field} must be a unix timestamp") from err
    if ts < 0:
        raise RISMessageError(f"{field} must be non-negative")
    return int(ts * 1_000_000_000)


def _structured_path(path: object, memory_bytes: int) -> tuple[tuple[ASPathSegment, ...], int]:
    """Preserve RIS AS_SET boundaries; the source does not encode confeds."""
    hops = _bounded_list(path, "data.path", memory_bytes // 128)
    # Charge the complete representation BEFORE typed allocation. This is
    # conservative Python object/list/tuple workspace, not path truncation.
    charge = 128
    for hop in hops:
        charge += 128
        if isinstance(hop, list):
            charge += len(hop) * 64
        if charge > memory_bytes:
            raise RISMessageError("data.path exceeds message memory admission")
    out: list[ASPathSegment] = []
    sequence: list[int] = []
    for hop in hops:
        if isinstance(hop, list):
            if not hop:
                raise RISMessageError("data.path AS_SET is empty")
            if sequence:
                out.append(ASPathSegment(AS_SEQUENCE, tuple(sequence)))
                sequence = []
            if any(value in (None, "") for value in hop):
                raise RISMessageError("data.path AS_SET has an absent ASN")
            out.append(ASPathSegment(AS_SET, tuple(_asn(asn, "data.path[]") for asn in hop)))
        else:
            if hop in (None, ""):
                raise RISMessageError("data.path has an absent ASN")
            sequence.append(_asn(hop, "data.path[]"))
    if sequence:
        out.append(ASPathSegment(AS_SEQUENCE, tuple(sequence)))
    return tuple(out), charge


def parse_ris_message(
    obj: object, *, memory_bytes: int = DEFAULT_RIS_MEMORY_BYTES
) -> list[BGPRoute]:
    """Normalize one RIS Live message into zero or more announced routes."""
    try:
        return _parse_ris_message(obj, memory_bytes)
    except (RISMessageError, TypeError, ValueError, KeyError) as err:
        _log.warning("skipping malformed RIS Live message", error=str(err))
        return []


def _parse_ris_message(obj: object, memory_bytes: int) -> list[BGPRoute]:
    msg = _as_dict(obj, "message")
    if msg.get("type") != "ris_message":
        return []
    data = _as_dict(msg.get("data", {}), "data")
    if data.get("type") != "UPDATE":
        return []

    if isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or memory_bytes <= 0:
        raise RISMessageError("message memory admission must be a positive integer")
    path, charged = _structured_path(data.get("path", []), memory_bytes)
    as_path = [asn for segment in path for asn in segment.values]
    peer_addr = _string(data.get("peer", ""), "data.peer")
    peer_asn = _asn(data.get("peer_asn"), "data.peer_asn")
    # DPR-294: keep which RIS collector saw the update, so a live event says
    # where it came from instead of only what the config filtered on.
    host = _string(data.get("host", ""), "data.host")
    if len(host) > MAX_RIS_HOST_LENGTH:
        raise RISMessageError(f"data.host is longer than {MAX_RIS_HOST_LENGTH} characters")
    event_time_unix_nano = _timestamp_unix_nano(
        data.get("timestamp", msg.get("timestamp")), "data.timestamp"
    )

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
            prefix = _string(prefix, "data.announcements[].prefixes[]")
            charged += 1024 + len(prefix) * 4 + len(as_path) * 8
            if charged > memory_bytes:
                raise RISMessageError("announced routes exceed message memory admission")
            routes.append(
                BGPRoute(
                    prefix=prefix,
                    as_path=list(as_path),
                    as_path_segments=path,
                    peer_asn=peer_asn,
                    peer_address=peer_addr,
                    event_time_unix_nano=event_time_unix_nano,
                    collector=host,
                )
            )
    return routes


def iter_updates(
    messages: Iterable[str],
    *,
    memory_bytes: int = DEFAULT_RIS_MEMORY_BYTES,
) -> Iterator[BGPRoute]:
    """Yield routes from an iterable of RIS Live JSON message strings (a live
    socket or a recorded replay). Malformed lines are logged and skipped."""
    for raw in messages:
        raw = raw.strip()
        if not raw:
            continue
        # Reserve conservative JSON-object workspace before json.loads. The
        # remaining budget still covers the complete normalized result, so
        # replay and live input cannot spend the same admission twice.
        if isinstance(memory_bytes, bool) or not isinstance(memory_bytes, int) or memory_bytes <= 0:
            _log.warning("refusing RIS input with invalid message memory admission")
            return
        if len(raw) > memory_bytes // 64:
            _log.warning("skipping unadmitted RIS Live message", memory_bytes=memory_bytes)
            continue
        try:
            source_charge = len(raw.encode("utf-8")) * 64
        except UnicodeError:
            _log.warning("skipping non-UTF8 RIS Live message")
            continue
        remaining = memory_bytes - source_charge
        if remaining <= 0:
            _log.warning("skipping unadmitted RIS Live message", memory_bytes=memory_bytes)
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as err:
            _log.warning("skipping malformed RIS Live message", error=str(err))
            continue
        yield from parse_ris_message(obj, memory_bytes=remaining)


class RISLiveClient:
    """Live RIS Live websocket adapter with reconnect/backoff.

    ``websockets`` ships in the pinned ``rislive`` extra; it is imported lazily so the parsing
    core stays usable (and testable) without it.
    """

    def __init__(
        self,
        url: str = RIS_LIVE_URL,
        host: str | None = None,
        max_backoff: float = 30.0,
        memory_bytes: int = DEFAULT_RIS_MEMORY_BYTES,
    ):
        self._url = url
        self._host = host
        self._max_backoff = max_backoff
        self._memory_bytes = memory_bytes

    def _subscribe_messages(self) -> list[str]:
        host = {"host": self._host} if self._host else {}
        # Subscription payloads are public: tenant prefix selection stays in PrefixMonitor.
        return [json.dumps({"type": "ris_subscribe", "data": {"type": "UPDATE"} | host})]

    def messages(self) -> Iterator[str]:
        """Yield raw JSON messages from the socket, reconnecting forever with
        exponential backoff. Requires the ``websockets`` package."""
        try:
            from websockets.sync.client import connect
        except ImportError as err:  # pragma: no cover - exercised only in live mode
            raise RuntimeError(
                "RIS Live live mode requires the pinned 'rislive' extra "
                "(pip install -e '.[rislive]' from analyzer/); "
                "use --replay for recorded captures"
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
        return iter_updates(self.messages(), memory_bytes=self._memory_bytes)
