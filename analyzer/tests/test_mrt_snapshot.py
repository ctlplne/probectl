# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Whole-source framing is distinct from best-effort anomaly observations."""

import io
import ipaddress
import struct

from mrt_fixtures import bgp4mp_update_as4, peer_index_table, rib_ipv4

from probectl_analyzer.mrt import MRTError, MRTReader


def record(subtype: int, body: bytes, timestamp: int = 0) -> bytes:
    return struct.pack(">IHHI", timestamp, 13, subtype, len(body)) + body


def test_snapshot_keeps_complete_binary_peer_identity_and_empty_presence():
    view = bytes(range(256)) * 255 + bytes(range(255))  # full uint16 view length
    body = struct.pack(">IH", 0, len(view)) + view + struct.pack(">H", 2)
    body += struct.pack(">BI", 2, 0) + ipaddress.ip_address("192.0.2.1").packed
    body += struct.pack(">I", 0)
    body += struct.pack(">BI", 3, 0xFFFFFFFF)
    body += ipaddress.ip_address("::ffff:192.0.2.1").packed
    body += struct.pack(">I", 0xFFFFFFFF)
    reader = MRTReader()
    stream = reader.stream_snapshot(io.BytesIO(record(1, body, 0xFFFFFFFF)))
    assert not reader.snapshot_complete
    assert list(stream) == []
    assert reader.snapshot_complete
    assert reader.snapshot_view_name == view
    assert reader.snapshot_collector_identifier == 0
    assert reader.snapshot_observed_unix_nano == 0xFFFFFFFF * 1_000_000_000
    assert [(p.asn, p.bgp_identifier) for p in reader.snapshot_peers] == [
        (0, 0),
        (0xFFFFFFFF, 0xFFFFFFFF),
    ]
    assert ipaddress.ip_address(reader.snapshot_peers[1].address).version == 6
    # An explicitly empty table has a source clock and no invented peer.
    empty = MRTReader()
    assert list(empty.stream_snapshot(io.BytesIO(record(1, struct.pack(">IHH", 0, 0, 0))))) == []
    assert empty.snapshot_complete and empty.snapshot_peers == ()
    assert empty.snapshot_observed_unix_nano == 0
    assert empty.snapshot_view_name == b""


def test_snapshot_refuses_late_skipped_records_and_requires_complete_eof():
    good = peer_index_table() + rib_ipv4("192.0.2.0/24", [0xFFFFFFFF, 64496])
    for tail in (
        record(2, b"\x00"),
        record(99, b""),
        peer_index_table(),
        bgp4mp_update_as4("203.0.113.0/24", [64496]),
        struct.pack(">IHHI", 0, 13, 2, 0xFFFFFFFF),
        b"truncated",
    ):
        reader = MRTReader()
        stream = reader.stream_snapshot(io.BytesIO(good + tail))
        assert next(stream).as_path == [0xFFFFFFFF, 64496]
        assert not reader.snapshot_complete
        refused = False
        try:
            list(stream)
        except MRTError:
            refused = True
        assert (
            refused and not reader.snapshot_complete
        ), "partial MRT source acquired complete status"
    for data in (b"", rib_ipv4("192.0.2.0/24", [64496])):
        reader = MRTReader()
        refused = False
        try:
            list(reader.stream_snapshot(io.BytesIO(data)))
        except MRTError:
            refused = True
        assert (
            refused and not reader.snapshot_complete
        ), "absent MRT source acquired empty complete status"
    reader = MRTReader()
    stream = reader.stream_snapshot(io.BytesIO(good))
    assert next(stream).prefix == "192.0.2.0/24"
    assert not reader.snapshot_complete  # abandoning a valid stream is incomplete
    assert list(stream) == [] and reader.snapshot_complete
    # The existing anomaly reader still tolerates an individually bad record.
    assert len(list(MRTReader().stream(io.BytesIO(good + record(2, b"\x00"))))) == 1
