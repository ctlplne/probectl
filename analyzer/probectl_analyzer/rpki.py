# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""RPKI route-origin validation (RFC 6811) against a VRP set.

A *VRP* (Validated ROA Payload) is ``(prefix, max_length, asn)``. The analyzer
loads VRPs from a validator export (the ``rpki-client`` / Routinator JSON
format) and checks each announcement offline — the "run a validator, check
ROAs" of S14, with the network fetch kept optional so a down validator degrades
to ``unknown`` rather than breaking analysis (CLAUDE.md §7 guardrail 10).
"""

from __future__ import annotations

import codecs
import ipaddress
import json
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import IO

from .events import RPKIStatus

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# DPR-055: a real validator export is ~100 MB / 600k ROAs today. It is streamed,
# never materialized, and bounded so a hostile or runaway source cannot exhaust
# the sidecar; a run that hits the bound degrades to RPKI unknown like any other
# fetch failure (CLAUDE.md §7 guardrail 10).
MAX_VRP_BYTES = 1 << 30
_STREAM_CHUNK = 1 << 16
_HEADER_LIMIT = 1 << 20  # metadata before the "roas" array must fit here
_ROAS_KEY = re.compile(r'"roas"\s*:\s*\[')
_SEPARATORS = re.compile(r"[\s,]*")


class VRPError(ValueError):
    """The VRP export is malformed, truncated, or larger than MAX_VRP_BYTES."""


def iter_roas(
    fp: IO[bytes], *, max_bytes: int = MAX_VRP_BYTES, chunk_size: int = _STREAM_CHUNK
) -> Iterator[dict]:
    """Yield the ROA entries of a validator export without loading it whole.

    Accepts both export shapes — ``{"roas": [...]}`` (rpki-client / Routinator /
    Cloudflare) and a bare array — and parses one entry at a time from a small
    rolling buffer, so memory stays proportional to one ROA, not the export.
    """
    decoder = json.JSONDecoder()
    utf8 = codecs.getincrementaldecoder("utf-8")()
    buf = ""
    total = 0
    eof = False

    def fill() -> bool:
        nonlocal buf, total, eof
        if eof:
            return False
        raw = fp.read(chunk_size)
        if isinstance(raw, str):  # text streams (tests, str-returning fakes)
            raw = raw.encode("utf-8")
        if not raw:
            eof = True
            buf += utf8.decode(b"", final=True)
            return False
        total += len(raw)
        if total > max_bytes:
            raise VRPError(f"VRP export exceeds the {max_bytes}-byte bound")
        buf += utf8.decode(raw)
        return True

    # Locate the array: a bare array starts the document; an object carries it
    # under "roas" within a small metadata header.
    idx = -1
    while idx < 0:
        stripped = buf.lstrip()
        if stripped.startswith("["):
            idx = len(buf) - len(stripped) + 1
            break
        m = _ROAS_KEY.search(buf)
        if m:
            idx = m.end()
            break
        if len(buf) > _HEADER_LIMIT:
            raise VRPError('no "roas" array within the first MiB of the VRP export')
        if not fill():
            raise VRPError("VRP export has no ROA array")

    while True:
        idx = _SEPARATORS.match(buf, idx).end()
        if idx >= len(buf):
            if not fill():
                raise VRPError("truncated VRP export (array never closed)")
            continue
        if buf[idx] == "]":
            return
        try:
            obj, end = decoder.raw_decode(buf, idx)
        except json.JSONDecodeError as err:
            if fill():  # the entry may straddle the chunk boundary
                continue
            raise VRPError(f"malformed or truncated VRP export: {err.msg}") from err
        if isinstance(obj, dict):
            yield obj
        idx = end
        if idx > chunk_size:
            buf = buf[idx:]
            idx = 0


def overlapping(monitored: Iterable[str]) -> Callable[[IPNetwork], bool]:
    """Predicate keeping every ROA that can influence a monitored prefix.

    The monitor validates only announcements that fall within a monitored
    prefix M. A ROA covering such an announcement either covers M or lies
    within M, so keeping exactly the ROAs that overlap M yields the same
    RFC 6811 verdicts as the full export for every validated announcement.
    """
    nets = [ipaddress.ip_network(p, strict=False) for p in monitored]

    def keep(roa: IPNetwork) -> bool:
        for m in nets:
            if roa.version != m.version:
                continue
            if roa.subnet_of(m) or m.subnet_of(roa):  # type: ignore[arg-type]
                return True
        return False

    return keep


def _parse_asn(value: object) -> int:
    """Accept 13335, "13335", or "AS13335"."""
    if isinstance(value, int):
        return value
    s = str(value).upper().removeprefix("AS").strip()
    return int(s)


@dataclass(frozen=True)
class ROA:
    network: IPNetwork
    max_length: int
    asn: int


def _roa_from_dict(r: dict) -> ROA:
    net = ipaddress.ip_network(r["prefix"], strict=False)
    max_len = int(r.get("maxLength", r.get("max_length", net.prefixlen)))
    return ROA(network=net, max_length=max_len, asn=_parse_asn(r["asn"]))


class VRPSet:
    """A set of validated ROA payloads supporting RFC 6811 origin validation."""

    def __init__(self, roas: list[ROA], scanned: int | None = None):
        self._roas = list(roas)
        # scanned counts every ROA read from the source, kept or not (logging).
        self.scanned = len(self._roas) if scanned is None else scanned

    def __len__(self) -> int:
        return len(self._roas)

    @classmethod
    def from_dicts(cls, roas: list[dict]) -> VRPSet:
        return cls([_roa_from_dict(r) for r in roas])

    @classmethod
    def from_json(cls, text: str) -> VRPSet:
        data = json.loads(text)
        roas = data["roas"] if isinstance(data, dict) else data
        return cls.from_dicts(roas)

    @classmethod
    def from_stream(
        cls,
        fp: IO[bytes],
        *,
        keep: Callable[[IPNetwork], bool] | None = None,
        max_bytes: int = MAX_VRP_BYTES,
    ) -> VRPSet:
        """Build the set from an export stream, keeping only ROAs ``keep`` accepts.

        This is the production loader (DPR-055): the export is parsed one entry
        at a time and filtered as it streams, so a full validator export costs
        a few MB of memory instead of the whole document as Python objects.
        """
        out: list[ROA] = []
        scanned = 0
        for entry in iter_roas(fp, max_bytes=max_bytes):
            scanned += 1
            roa = _roa_from_dict(entry)
            if keep is None or keep(roa.network):
                out.append(roa)
        return cls(out, scanned=scanned)

    @classmethod
    def from_file(cls, path: str, *, keep: Callable[[IPNetwork], bool] | None = None) -> VRPSet:
        with open(path, "rb") as fh:
            return cls.from_stream(fh, keep=keep)

    def validate(self, prefix: str, origin_asn: int) -> RPKIStatus:
        """Return the RFC 6811 validation state for an (prefix, origin) pair."""
        try:
            ann = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return RPKIStatus.UNKNOWN

        covering = [
            r for r in self._roas if r.network.version == ann.version and _covers(r.network, ann)
        ]
        if not covering:
            return RPKIStatus.NOT_FOUND
        for r in covering:
            if r.asn == origin_asn and ann.prefixlen <= r.max_length:
                return RPKIStatus.VALID
        return RPKIStatus.INVALID


def _covers(roa_net: IPNetwork, ann: IPNetwork) -> bool:
    """True when the ROA prefix is equal-or-less-specific than the announcement
    (i.e. the announced prefix falls within the ROA prefix)."""
    if ann.prefixlen < roa_net.prefixlen:
        return False
    return ann.subnet_of(roa_net)  # type: ignore[arg-type]
