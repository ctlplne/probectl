"""A streaming MRT parser (RFC 6396) for RouteViews / RIPE RIS dumps.

It yields one :class:`BGPRoute` at a time and never materializes a full RIB in
memory (S14 watch-out: MRT dumps are large — stream, don't load). Only the record
types netctl needs are decoded — TABLE_DUMP_V2 RIB (IPv4/IPv6) and BGP4MP UPDATE
messages — and every read is bounds-checked because collector data is untrusted
(CLAUDE.md §7 guardrail 10). A malformed record is logged and skipped rather than
aborting the whole stream.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO

from .log import get_logger

_log = get_logger("netctl.analyzer.mrt")

# MRT record types.
TYPE_TABLE_DUMP_V2 = 13
TYPE_BGP4MP = 16

# TABLE_DUMP_V2 subtypes.
SUB_PEER_INDEX_TABLE = 1
SUB_RIB_IPV4_UNICAST = 2
SUB_RIB_IPV6_UNICAST = 4

# BGP4MP subtypes.
SUB_BGP4MP_MESSAGE = 1
SUB_BGP4MP_MESSAGE_AS4 = 4

# BGP path-attribute type codes.
ATTR_AS_PATH = 2
ATTR_MP_REACH_NLRI = 14

# MRT address families.
AFI_IPV4 = 1
AFI_IPV6 = 2

BGP_UPDATE = 2


class MRTError(Exception):
    """A malformed MRT record."""


@dataclass
class BGPRoute:
    """One announced prefix with its AS path, as seen by a collector peer."""

    prefix: str
    as_path: list[int] = field(default_factory=list)
    peer_asn: int = 0
    peer_address: str = ""
    collector_id: int = 0

    @property
    def origin_asn(self) -> int:
        return self.as_path[-1] if self.as_path else 0


class _Reader:
    """A bounds-checked big-endian cursor over untrusted bytes."""

    def __init__(self, data: bytes):
        self._d = data
        self._i = 0

    def read(self, n: int) -> bytes:
        if n < 0 or self._i + n > len(self._d):
            raise MRTError("read past end of record")
        b = self._d[self._i : self._i + n]
        self._i += n
        return b

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.read(4))[0]

    def remaining(self) -> int:
        return len(self._d) - self._i

    def rest(self) -> bytes:
        b = self._d[self._i :]
        self._i = len(self._d)
        return b

    def read_prefix(self, afi: int) -> str:
        """Decode an MRT/BGP length-prefixed NLRI prefix into CIDR text."""
        bits = self.u8()
        max_bytes = 16 if afi == AFI_IPV6 else 4
        if bits > max_bytes * 8:
            raise MRTError(f"prefix length {bits} out of range")
        nbytes = (bits + 7) // 8
        raw = self.read(nbytes)
        padded = raw + bytes(max_bytes - nbytes)
        if afi == AFI_IPV6:
            ip: object = ipaddress.IPv6Address(padded)
        else:
            ip = ipaddress.IPv4Address(padded)
        return f"{ip}/{bits}"


class MRTReader:
    """Stateful streaming reader (keeps the PEER_INDEX_TABLE for peer lookups)."""

    def __init__(self) -> None:
        self._peers: list[tuple[int, str]] = []
        self._collector_id = 0

    def stream(self, fp: BinaryIO) -> Iterator[BGPRoute]:
        while True:
            header = fp.read(12)
            if not header:
                return
            if len(header) < 12:
                raise MRTError("truncated MRT common header")
            _ts, mtype, subtype, length = struct.unpack(">IHHI", header)
            body = fp.read(length)
            if len(body) < length:
                raise MRTError("truncated MRT record body")
            try:
                yield from self._dispatch(mtype, subtype, body)
            except MRTError as err:
                # One bad record must not kill a multi-gigabyte dump.
                _log.warning(
                    "skipping malformed MRT record",
                    mtype=mtype,
                    subtype=subtype,
                    error=str(err),
                )

    def _dispatch(self, mtype: int, subtype: int, body: bytes) -> Iterator[BGPRoute]:
        if mtype == TYPE_TABLE_DUMP_V2:
            if subtype == SUB_PEER_INDEX_TABLE:
                self._parse_peer_index(body)
            elif subtype == SUB_RIB_IPV4_UNICAST:
                yield from self._parse_rib(body, AFI_IPV4)
            elif subtype == SUB_RIB_IPV6_UNICAST:
                yield from self._parse_rib(body, AFI_IPV6)
        elif mtype == TYPE_BGP4MP:
            if subtype in (SUB_BGP4MP_MESSAGE, SUB_BGP4MP_MESSAGE_AS4):
                yield from self._parse_bgp4mp(body, four_byte=subtype == SUB_BGP4MP_MESSAGE_AS4)

    def _parse_peer_index(self, body: bytes) -> None:
        r = _Reader(body)
        self._collector_id = r.u32()
        view_len = r.u16()
        r.read(view_len)
        count = r.u16()
        peers: list[tuple[int, str]] = []
        for _ in range(count):
            peer_type = r.u8()
            r.u32()  # peer BGP id
            if peer_type & 0x01:
                addr = str(ipaddress.IPv6Address(r.read(16)))
            else:
                addr = str(ipaddress.IPv4Address(r.read(4)))
            asn = r.u32() if peer_type & 0x02 else r.u16()
            peers.append((asn, addr))
        self._peers = peers

    def _parse_rib(self, body: bytes, afi: int) -> Iterator[BGPRoute]:
        r = _Reader(body)
        r.u32()  # sequence number
        prefix = r.read_prefix(afi)
        entry_count = r.u16()
        for _ in range(entry_count):
            peer_index = r.u16()
            r.u32()  # originated time
            attr_len = r.u16()
            attrs = r.read(attr_len)
            as_path = _as_path_from_attrs(attrs, four_byte=True)
            peer_asn, peer_addr = (
                self._peers[peer_index] if peer_index < len(self._peers) else (0, "")
            )
            yield BGPRoute(
                prefix=prefix,
                as_path=as_path,
                peer_asn=peer_asn,
                peer_address=peer_addr,
                collector_id=self._collector_id,
            )

    def _parse_bgp4mp(self, body: bytes, four_byte: bool) -> Iterator[BGPRoute]:
        r = _Reader(body)
        peer_as = r.u32() if four_byte else r.u16()
        _local_as = r.u32() if four_byte else r.u16()
        r.u16()  # interface index
        afi = r.u16()
        addr_len = 16 if afi == AFI_IPV6 else 4
        peer_ip = (
            str(ipaddress.IPv6Address(r.read(16)))
            if afi == AFI_IPV6
            else str(ipaddress.IPv4Address(r.read(4)))
        )
        r.read(addr_len)  # local ip
        r.read(16)  # BGP marker
        r.u16()  # message length
        if r.u8() != BGP_UPDATE:
            return
        yield from self._parse_update(r, peer_as, peer_ip, four_byte)

    def _parse_update(
        self, r: _Reader, peer_as: int, peer_ip: str, four_byte: bool
    ) -> Iterator[BGPRoute]:
        withdrawn_len = r.u16()
        r.read(withdrawn_len)  # withdrawals — not monitored here
        total_attr_len = r.u16()
        attrs = r.read(total_attr_len)
        as_path = _as_path_from_attrs(attrs, four_byte=four_byte)

        prefixes = list(_mp_reach_prefixes(attrs))
        nlri = _Reader(r.rest())  # IPv4 NLRI trailing the attributes
        while nlri.remaining() > 0:
            prefixes.append(nlri.read_prefix(AFI_IPV4))

        for prefix in prefixes:
            yield BGPRoute(
                prefix=prefix,
                as_path=as_path,
                peer_asn=peer_as,
                peer_address=peer_ip,
                collector_id=self._collector_id,
            )


def stream_mrt(fp: BinaryIO) -> Iterator[BGPRoute]:
    """Convenience wrapper: stream routes from an MRT file object."""
    return MRTReader().stream(fp)


def _iter_attrs(attrs: bytes) -> Iterator[tuple[int, bytes]]:
    r = _Reader(attrs)
    while r.remaining() > 0:
        flags = r.u8()
        typ = r.u8()
        alen = r.u16() if flags & 0x10 else r.u8()
        yield typ, r.read(alen)


def _as_path_from_attrs(attrs: bytes, four_byte: bool) -> list[int]:
    for typ, val in _iter_attrs(attrs):
        if typ == ATTR_AS_PATH:
            return _parse_as_path(val, four_byte)
    return []


def _parse_as_path(val: bytes, four_byte: bool) -> list[int]:
    r = _Reader(val)
    path: list[int] = []
    while r.remaining() > 0:
        r.u8()  # segment type (AS_SET / AS_SEQUENCE) — flattened
        seg_len = r.u8()
        for _ in range(seg_len):
            path.append(r.u32() if four_byte else r.u16())
    return path


def _mp_reach_prefixes(attrs: bytes) -> list[str]:
    for typ, val in _iter_attrs(attrs):
        if typ != ATTR_MP_REACH_NLRI:
            continue
        r = _Reader(val)
        afi = r.u16()
        r.u8()  # SAFI
        nh_len = r.u8()
        r.read(nh_len)  # next hop
        r.u8()  # reserved / SNPA count
        out: list[str] = []
        while r.remaining() > 0:
            out.append(r.read_prefix(AFI_IPV6 if afi == AFI_IPV6 else AFI_IPV4))
        return out
    return []
