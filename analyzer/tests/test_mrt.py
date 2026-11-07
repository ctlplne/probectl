# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Streaming MRT parser tests against built RFC 6396 fixtures."""

from __future__ import annotations

import io
import struct

import pytest
from mrt_fixtures import bgp4mp_update_as4, peer_index_table, rib_ipv4

from probectl_analyzer.mrt import MAX_MRT_RECORD_LENGTH, MRTError, MRTReader, stream_mrt


class CountingReader:
    def __init__(self, header: bytes):
        self._header = header
        self._sent_header = False
        self.read_calls: list[int] = []

    def read(self, n: int) -> bytes:
        self.read_calls.append(n)
        if not self._sent_header:
            self._sent_header = True
            return self._header
        return b""


def test_parses_table_dump_v2_rib_with_peer_attribution():
    event_ts = 1_777_000_900
    data = peer_index_table(peer_as=64511, peer_ip="192.0.2.1") + rib_ipv4(
        "192.0.2.0/24", [64511, 64500, 64496], ts=event_ts
    )
    routes = list(stream_mrt(io.BytesIO(data)))

    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "192.0.2.0/24"
    assert r.as_path == [64511, 64500, 64496]
    assert r.origin_asn == 64496
    assert r.peer_asn == 64511
    assert r.peer_address == "192.0.2.1"
    assert r.event_time_unix_nano == event_ts * 1_000_000_000


def test_parses_bgp4mp_as4_update():
    event_ts = 1_777_000_901
    data = bgp4mp_update_as4("198.51.100.0/24", [64511, 64502], peer_as=64511, ts=event_ts)
    routes = list(stream_mrt(io.BytesIO(data)))

    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "198.51.100.0/24"
    assert r.as_path == [64511, 64502]
    assert r.origin_asn == 64502
    assert r.peer_asn == 64511
    assert r.event_time_unix_nano == event_ts * 1_000_000_000


def test_streams_multiple_records_without_buffering():
    data = (
        peer_index_table()
        + rib_ipv4("192.0.2.0/24", [64496])
        + rib_ipv4("203.0.113.0/24", [64511, 64497])
        + bgp4mp_update_as4("198.51.100.0/24", [64511, 64502])
    )
    # stream_mrt returns a generator — it yields lazily, never building the full RIB.
    gen = stream_mrt(io.BytesIO(data))
    prefixes = [r.prefix for r in gen]
    assert prefixes == ["192.0.2.0/24", "203.0.113.0/24", "198.51.100.0/24"]


def test_malformed_record_is_skipped_not_fatal():
    # A record whose declared length is honored but whose body is too short to be
    # a valid RIB: the parser logs and skips it, then continues with the good one.
    bad = struct.pack(">IHHI", 0, 13, 2, 3) + b"\x00\x00\x00"  # truncated RIB body
    data = bad + rib_ipv4("192.0.2.0/24", [64496])
    routes = list(stream_mrt(io.BytesIO(data)))
    assert [r.prefix for r in routes] == ["192.0.2.0/24"]


def test_oversized_record_rejected_before_attacker_sized_read():
    header = struct.pack(">IHHI", 0, 13, 2, 0xFFFFFFFF)
    reader = CountingReader(header)

    with pytest.raises(MRTError, match="exceeds max"):
        list(stream_mrt(reader))

    assert reader.read_calls == [12]


def test_oversized_seekable_record_is_skipped_without_body_read():
    header = struct.pack(">IHHI", 0, 13, 2, MAX_MRT_RECORD_LENGTH + 1)
    data = header + rib_ipv4("192.0.2.0/24", [64496])

    assert list(stream_mrt(io.BytesIO(data))) == []


@pytest.mark.parametrize("micros", [0, 1, 123456, 999999])
def test_bgp4mp_extended_timestamp_preserves_route_and_time(micros):
    ts = 1_793_059_200
    regular = bgp4mp_update_as4("192.0.2.0/24", [64511, 64496], ts=ts)
    body = struct.pack(">I", micros) + regular[12:]
    extended = struct.pack(">IHHI", ts, 17, 4, len(body)) + body
    routes = list(stream_mrt(io.BytesIO(extended)))
    assert len(routes) == 1
    assert routes[0].prefix == "192.0.2.0/24"
    assert routes[0].as_path == [64511, 64496]
    assert routes[0].peer_asn == 64511
    assert routes[0].event_time_unix_nano == ts * 1_000_000_000 + micros * 1000


def test_short_extended_timestamp_does_not_consume_next_record():
    short = struct.pack(">IHHI", 0, 17, 4, 3) + b"abc"
    good = bgp4mp_update_as4("198.51.100.0/24", [64496])
    assert [r.prefix for r in stream_mrt(io.BytesIO(short + good))] == ["198.51.100.0/24"]


def test_rib_late_entry_and_trailing_bytes_never_publish_a_record_prefix():
    valid = rib_ipv4("192.0.2.0/24", [64511, 64496])
    body = bytearray(valid[12:])
    # Sequence(4), prefix length+octets(4), then entry count(2).
    body[8:10] = struct.pack(">H", 2)
    malformed = struct.pack(">IHHI", 0, 13, 2, len(body) + 1) + body + b"\x00"
    padded = struct.pack(">IHHI", 0, 13, 2, len(valid[12:]) + 1) + valid[12:] + b"\x00"
    good = rib_ipv4("198.51.100.0/24", [64511, 64502])
    for bad in (malformed, padded):
        routes = list(stream_mrt(io.BytesIO(peer_index_table() + bad + good)))
        assert [route.prefix for route in routes] == [
            "198.51.100.0/24"
        ], "malformed RIB record published an earlier prefix"


def test_peer_index_late_failure_keeps_whole_original_collector_and_peer_identity():
    original = peer_index_table(peer_as=64511, peer_ip="192.0.2.1")
    replacement = bytearray(peer_index_table(peer_as=64512, peer_ip="192.0.2.2")[12:])
    replacement[:4] = struct.pack(">I", 123456789)
    malformed = struct.pack(">IHHI", 0, 13, 1, len(replacement) - 1) + replacement[:-1]
    padded = struct.pack(">IHHI", 0, 13, 1, len(replacement) + 1) + replacement + b"\x00"
    for bad in (malformed, padded):
        reader = MRTReader()
        expected = list(reader.stream(io.BytesIO(original + rib_ipv4("192.0.2.0/24", [64496]))))[0]
        route = list(reader.stream(io.BytesIO(bad + rib_ipv4("198.51.100.0/24", [64502]))))[0]
        assert (route.collector_id, route.peer_asn, route.peer_address) == (
            expected.collector_id,
            64511,
            "192.0.2.1",
        ), "malformed peer table mixed collector and peer generations"


def test_rib_rejects_undefined_peer_in_an_existing_peer_table():
    valid = rib_ipv4("192.0.2.0/24", [64511, 64496])
    body = bytearray(valid[12:])
    body[10:12] = struct.pack(">H", 65535)
    invalid = struct.pack(">IHHI", 0, 13, 2, len(body)) + body
    assert (
        list(stream_mrt(io.BytesIO(peer_index_table() + invalid))) == []
    ), "RIB record invented an absent peer identity"


def test_empty_peer_replacement_cannot_restore_unknown_peer_routes():
    empty_body = struct.pack(">IHH", 9, 0, 0)
    empty = struct.pack(">IHHI", 0, 13, 1, len(empty_body)) + empty_body
    data = peer_index_table() + empty + rib_ipv4("192.0.2.0/24", [64511, 64496])
    assert list(stream_mrt(io.BytesIO(data))) == [], (
        "explicit empty peer replacement allowed an unknown peer route"
    )
