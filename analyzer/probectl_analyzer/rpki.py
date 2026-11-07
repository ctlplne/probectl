# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""RPKI route-origin validation (RFC 6811) against a VRP set.

A *VRP* (Validated ROA Payload) is ``(prefix, max_length, asn)``. The analyzer
loads VRPs from a validator export (the ``rpki-client`` / Routinator JSON
format) and checks each announcement offline — the "run a validator, check
ROAs" of S14, with the network fetch kept optional so a down validator degrades
to ``unknown`` rather than breaking analysis (docs/guardrails.md G7-10).
"""

from __future__ import annotations

import codecs
import io
import ipaddress
import json
import re
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import IO

from .events import RPKIStatus

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# DPR-055: a real validator export is ~100 MB / 600k ROAs today. It is streamed,
# never materialized, and bounded so a hostile or runaway source cannot exhaust
# the sidecar; a run that hits the bound degrades to RPKI unknown like any other
# fetch failure (docs/guardrails.md G7-10).
MAX_VRP_BYTES = 1 << 30
_STREAM_CHUNK = 1 << 16
_JSON_STRING_SPECIAL = re.compile(r'["\\]')
_JSON_STRUCTURAL = re.compile(r'["\\{}\[\]:,]')
_JSON_SCALAR_END = re.compile(r"[ \t\r\n,\]}:]")
# Complete values are framed in one linear pass before one JSON decode. Deep
# invalid input and representation costs fail admission before materialization.


class VRPError(ValueError):
    """The VRP export is malformed, truncated, or larger than MAX_VRP_BYTES."""


class _VRPJSONStream:
    """Bounded incremental JSON values; never buffer a complete VRP export."""

    def __init__(self, fp: IO[bytes], max_bytes: int, chunk_size: int):
        if max_bytes <= 0 or chunk_size <= 0:
            raise VRPError("VRP source admission must be positive")
        self.fp = fp
        self.max_bytes = max_bytes
        self.chunk_size = min(chunk_size, max_bytes + 1)
        self.total = 0
        self.buf = ""
        self.pos = 0
        self.eof = False
        self.utf8 = codecs.getincrementaldecoder("utf-8")()
        self.decoder = json.JSONDecoder(
            object_pairs_hook=self._object, parse_constant=self._constant
        )

    @staticmethod
    def _object(pairs: list[tuple[str, object]]) -> dict:
        out: dict = {}
        for key, value in pairs:
            if key in out:
                raise VRPError("duplicate VRP JSON object key")
            out[key] = value
        return out

    @staticmethod
    def _constant(value: str):
        raise VRPError(f"non-JSON VRP constant {value}")

    def fill(self) -> bool:
        if self.eof:
            return False
        raw = self.fp.read(min(self.chunk_size, self.max_bytes - self.total + 1))
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        self.total += len(raw)
        if self.total > self.max_bytes:
            raise VRPError(f"VRP export exceeds the {self.max_bytes}-byte bound")
        self.eof = not raw
        try:
            self.buf += self.utf8.decode(raw, final=self.eof)
        except UnicodeError as err:
            raise VRPError("VRP export is not complete UTF-8") from err
        return not self.eof

    def compact(self) -> None:
        if self.pos > self.chunk_size:
            self.buf = self.buf[self.pos :]
            self.pos = 0

    def peek(self) -> str:
        while True:
            while self.pos < len(self.buf) and self.buf[self.pos] in " \t\r\n":
                self.pos += 1
            if self.pos < len(self.buf):
                return self.buf[self.pos]
            self.compact()
            if not self.fill():
                return ""

    def take(self, token: str) -> None:
        if self.peek() != token:
            raise VRPError(f"malformed or truncated VRP export: expected {token!r}")
        self.pos += 1
        self.compact()

    def value(self):
        if not self.peek():
            raise VRPError("malformed or truncated VRP export: missing value")
        fragments, end = self.value_end()
        fragments.append(self.buf[self.pos : end])
        try:
            value = self.decoder.decode("".join(fragments))
        except (ValueError, RecursionError) as err:
            raise VRPError("malformed VRP per-entry JSON value") from err
        self.pos = end
        self.compact()
        return value

    def value_end(self) -> tuple[list[str], int]:
        # Scan each character once before decoding a complete value once.
        # Large legitimate strings/metadata do not trigger quadratic retries
        # or inherit the former fixed one-MiB logical entry/header ceiling.
        start = self.pos
        fragments: list[str] = []
        first = self.buf[start]
        quoted = first == '"'
        compound = first in "[{"
        stack = [first] if compound else []
        in_string = quoted
        escaped = False
        index = start + 1 if quoted or compound else start
        charge = 256
        while True:
            if index == len(self.buf):
                # Retain each scanned chunk once, instead of repeatedly copying
                # an ever-growing value while waiting for its closing token.
                fragments.append(self.buf[self.pos : index])
                self.buf = ""
                self.pos = 0
                index = 0
                if self.fill():
                    continue
                if quoted or compound:
                    raise VRPError("truncated VRP per-entry JSON value")
                return fragments, index
            if escaped:
                escaped = False
                index += 1
                charge += 64
                continue
            pattern = _JSON_STRING_SPECIAL if in_string else _JSON_STRUCTURAL
            if not quoted and not compound:
                pattern = _JSON_SCALAR_END
            match = pattern.search(self.buf, index)
            boundary = match.start() if match else len(self.buf)
            charge += 64 * (boundary - index)
            if charge > max(MAX_VRP_BYTES, self.max_bytes):
                raise VRPError("VRP per-entry representation exceeds memory admission")
            index = boundary
            if match is None:
                continue
            char = self.buf[index]
            charge += 64 + (256 if not in_string else 0)
            if not quoted and not compound:
                return fragments, index
            if in_string:
                if char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                    if quoted:
                        return fragments, index + 1
            elif char == '"':
                in_string = True
            elif char in "[{":
                stack.append(char)
                if len(stack) > sys.getrecursionlimit():
                    raise VRPError("VRP per-entry nesting exceeds JSON runtime admission")
            elif char in "]}":
                if not stack or (stack[-1], char) not in (("[", "]"), ("{", "}")):
                    raise VRPError("mismatched VRP per-entry JSON delimiters")
                stack.pop()
                if not stack:
                    return fragments, index + 1
            index += 1

    def roas(self) -> Iterator[dict]:
        self.take("[")
        if self.peek() == "]":
            self.take("]")
            return
        while True:
            value = self.value()
            if not isinstance(value, dict):
                raise VRPError("every VRP entry must be an object")
            yield value
            if self.peek() == "]":
                self.take("]")
                return
            self.take(",")
            if self.peek() == "]":
                raise VRPError("trailing comma in VRP array")


def iter_roas(
    fp: IO[bytes], *, max_bytes: int = MAX_VRP_BYTES, chunk_size: int = _STREAM_CHUNK
) -> Iterator[dict]:
    """Stream both export shapes and validate the complete enclosing document.

    The production set is published only after this iterator finishes. Every
    entry, metadata value, delimiter, UTF-8 tail and total byte is checked;
    malformed tails cannot turn a partial source into a complete VRPSet.
    """
    stream = _VRPJSONStream(fp, max_bytes, chunk_size)
    if stream.peek() == "[":
        yield from stream.roas()
    elif stream.peek() == "{":
        stream.take("{")

        found = False
        seen: set[str] = set()
        key_memory = 0
        if stream.peek() != "}":
            while True:
                key = stream.value()
                if not isinstance(key, str) or key in seen:
                    raise VRPError("missing or duplicate VRP export key")
                key_memory += 128 + 4 * len(key)
                if key_memory > max(MAX_VRP_BYTES, max_bytes):
                    raise VRPError("VRP metadata keys exceed memory admission")
                seen.add(key)
                stream.take(":")
                if key == "roas":
                    found = True
                    yield from stream.roas()
                else:
                    stream.value()
                if stream.peek() == "}":
                    break
                stream.take(",")
                if stream.peek() == "}":
                    raise VRPError("trailing comma in VRP object")
        stream.take("}")
        if not found:
            raise VRPError("VRP export has no top-level ROA array")
    else:
        raise VRPError("VRP export has no ROA array")
    if stream.peek():
        raise VRPError("trailing data after complete VRP export")


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
    """Accept the full uint32 ASN range, including RFC 7607 AS0 ROAs."""
    if isinstance(value, bool):
        raise VRPError("VRP ASN must be an integer")
    text = str(value).strip().upper().removeprefix("AS").strip()
    if not text.removeprefix("+").isdecimal():
        raise VRPError("VRP ASN must be an integer")
    asn = int(text)
    if not 0 <= asn <= 0xFFFFFFFF:
        raise VRPError("VRP ASN is outside the uint32 range")
    return asn


@dataclass(frozen=True)
class ROA:
    network: IPNetwork
    max_length: int
    asn: int


def _roa_from_dict(r: dict) -> ROA:
    try:
        if not isinstance(r["prefix"], str):
            raise VRPError("VRP prefix must be a string")
        net = ipaddress.ip_network(r["prefix"], strict=False)
        value = r.get("maxLength", net.prefixlen)
        if isinstance(value, bool) or not str(value).strip().removeprefix("+").isdecimal():
            raise VRPError("VRP maxLength must be an integer")
        length = int(value)
        if not net.prefixlen <= length <= net.max_prefixlen:
            raise VRPError("VRP maxLength does not fit its prefix family")
        return ROA(network=net, max_length=length, asn=_parse_asn(r["asn"]))
    except (KeyError, TypeError, ValueError) as err:
        raise VRPError("malformed VRP entry") from err


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
        return cls.from_stream(io.BytesIO(text.encode("utf-8")))

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
