"""Builders that emit real MRT (RFC 6396) wire bytes for the parser tests.

Encoding the structures the parser decodes (TABLE_DUMP_V2 RIB + BGP4MP_AS4
UPDATE) keeps the fixtures transparent and the parser genuinely exercised — no
opaque committed binaries.
"""

from __future__ import annotations

import ipaddress
import struct

TYPE_TABLE_DUMP_V2 = 13
TYPE_BGP4MP = 16
SUB_PEER_INDEX_TABLE = 1
SUB_RIB_IPV4_UNICAST = 2
SUB_BGP4MP_MESSAGE_AS4 = 4


def _record(mtype: int, subtype: int, body: bytes, ts: int = 0) -> bytes:
    return struct.pack(">IHHI", ts, mtype, subtype, len(body)) + body


def _as_path_attr(asns: list[int]) -> bytes:
    seg = struct.pack(">BB", 2, len(asns)) + b"".join(struct.pack(">I", a) for a in asns)
    # flags=0x40 (well-known, transitive), type=2 (AS_PATH), 1-byte length.
    return struct.pack(">BBB", 0x40, 2, len(seg)) + seg


def _prefix(cidr: str) -> bytes:
    net = ipaddress.ip_network(cidr)
    nbytes = (net.prefixlen + 7) // 8
    return struct.pack(">B", net.prefixlen) + net.network_address.packed[:nbytes]


def peer_index_table(
    collector_id: int = 1, peer_as: int = 64511, peer_ip: str = "192.0.2.1"
) -> bytes:
    body = struct.pack(">I", collector_id) + struct.pack(">H", 0)  # collector id + empty view name
    body += struct.pack(">H", 1)  # one peer
    body += struct.pack(">B", 0x02)  # peer type: IPv4 address + 4-byte ASN
    body += struct.pack(">I", 0)  # peer BGP id
    body += ipaddress.IPv4Address(peer_ip).packed
    body += struct.pack(">I", peer_as)
    return _record(TYPE_TABLE_DUMP_V2, SUB_PEER_INDEX_TABLE, body)


def rib_ipv4(prefix: str, asns: list[int], peer_index: int = 0, seq: int = 0) -> bytes:
    attrs = _as_path_attr(asns)
    body = struct.pack(">I", seq) + _prefix(prefix) + struct.pack(">H", 1)
    body += struct.pack(">H", peer_index) + struct.pack(">I", 0)
    body += struct.pack(">H", len(attrs)) + attrs
    return _record(TYPE_TABLE_DUMP_V2, SUB_RIB_IPV4_UNICAST, body)


def bgp4mp_update_as4(
    prefix: str, asns: list[int], peer_as: int = 64511, peer_ip: str = "192.0.2.1"
) -> bytes:
    attrs = _as_path_attr(asns)
    update = struct.pack(">H", 0)  # no withdrawals
    update += struct.pack(">H", len(attrs)) + attrs
    update += _prefix(prefix)  # IPv4 NLRI
    msg = b"\xff" * 16 + struct.pack(">H", 19 + len(update)) + struct.pack(">B", 2) + update
    body = struct.pack(">I", peer_as) + struct.pack(">I", 0)  # peer/local AS
    body += struct.pack(">H", 0) + struct.pack(">H", 1)  # ifindex + AFI=IPv4
    body += ipaddress.IPv4Address(peer_ip).packed + ipaddress.IPv4Address("192.0.2.2").packed
    body += msg
    return _record(TYPE_BGP4MP, SUB_BGP4MP_MESSAGE_AS4, body)
