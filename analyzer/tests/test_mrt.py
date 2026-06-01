"""Streaming MRT parser tests against built RFC 6396 fixtures."""

from __future__ import annotations

import io

from mrt_fixtures import bgp4mp_update_as4, peer_index_table, rib_ipv4

from netctl_analyzer.mrt import stream_mrt


def test_parses_table_dump_v2_rib_with_peer_attribution():
    data = peer_index_table(peer_as=64511, peer_ip="192.0.2.1") + rib_ipv4(
        "192.0.2.0/24", [64511, 64500, 64496]
    )
    routes = list(stream_mrt(io.BytesIO(data)))

    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "192.0.2.0/24"
    assert r.as_path == [64511, 64500, 64496]
    assert r.origin_asn == 64496
    assert r.peer_asn == 64511
    assert r.peer_address == "192.0.2.1"


def test_parses_bgp4mp_as4_update():
    data = bgp4mp_update_as4("198.51.100.0/24", [64511, 64502], peer_as=64511)
    routes = list(stream_mrt(io.BytesIO(data)))

    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "198.51.100.0/24"
    assert r.as_path == [64511, 64502]
    assert r.origin_asn == 64502
    assert r.peer_asn == 64511


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
    import struct

    bad = struct.pack(">IHHI", 0, 13, 2, 3) + b"\x00\x00\x00"  # truncated RIB body
    data = bad + rib_ipv4("192.0.2.0/24", [64496])
    routes = list(stream_mrt(io.BytesIO(data)))
    assert [r.prefix for r in routes] == ["192.0.2.0/24"]
