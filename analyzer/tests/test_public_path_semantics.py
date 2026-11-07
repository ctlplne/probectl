# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Recorded public-source wire semantics, not a complete/current public RIB proof."""

import io
import ipaddress
import json
import struct

import pytest

from probectl_analyzer.__main__ import main
from probectl_analyzer.config import AnalyzerConfig
from probectl_analyzer.monitor import PrefixMonitor
from probectl_analyzer.mrt import stream_mrt
from probectl_analyzer.rislive import RISLiveClient, parse_ris_message


def _attribute(kind, value):
    return struct.pack(">BBH", 0x50, kind, len(value)) + value


def _segments(items, width=4):
    return b"".join(
        bytes((kind, len(values))) + b"".join(value.to_bytes(width, "big") for value in values)
        for kind, values in items
    )


def _update(attrs, width=4, withdrawals=b"", nlri=b"\x18\xc0\x00\x02"):
    # Independent RFC6396/RFC4271 framing, including actual negotiated width.
    update = len(withdrawals).to_bytes(2, "big") + withdrawals
    update += len(attrs).to_bytes(2, "big") + attrs + nlri
    message = b"\xff" * 16 + (19 + len(update)).to_bytes(2, "big") + b"\x02" + update
    body = (64511).to_bytes(width, "big") + bytes(width) + b"\x00\x00\x00\x01"
    body += ipaddress.ip_address("192.0.2.1").packed + ipaddress.ip_address("192.0.2.2").packed
    body += message
    return struct.pack(">IHHI", 1700000000, 16, 4 if width == 4 else 1, len(body)) + body


def _signature(route):
    return [(segment.kind, segment.values) for segment in route.as_path_segments]


def _ris(path):
    return {
        "type": "ris_message",
        "data": {
            "type": "UPDATE",
            "path": path,
            "announcements": [{"prefixes": ["192.0.2.0/24"]}],
        },
    }


def test_public_mrt_keeps_all_segments_prepends_and_full_asns():
    segments = [
        (3, (65000, 65001)),
        (2, (64511, 64511)),
        (1, (0, 4294967295)),
        (4, (65002, 65003)),
        (2, (4294967295,)),
    ]
    (route,) = stream_mrt(io.BytesIO(_update(_attribute(2, _segments(segments)))))
    assert _signature(route) == segments
    assert route.as_path == [asn for _, values in segments for asn in values]
    assert route.origin_known and route.origin_asn == 4294967295


def test_public_mrt_keeps_complete_large_wire_path_and_table_dump_width():
    values = [64511] * 15_999 + [4294967295]
    segments = [(2, tuple(values[i : i + 255])) for i in range(0, len(values), 255)]
    attrs = _attribute(2, _segments(segments))
    (route,) = stream_mrt(io.BytesIO(_update(attrs)))
    assert _signature(route) == segments and route.as_path == values
    # TABLE_DUMP_V2 always stores four-octet path ASNs (RFC6396 §4.3.4).
    body = bytes(4) + b"\x18\xc0\x00\x02\x00\x01" + bytes(6)
    body += len(attrs).to_bytes(2, "big") + attrs
    record = struct.pack(">IHHI", 1700000000, 13, 2, len(body)) + body
    (route,) = stream_mrt(io.BytesIO(record))
    assert _signature(route) == segments and route.as_path == values


@pytest.mark.parametrize(
    "segments", [[], [(1, (64500, 64501))], [(3, (64500,))], [(2, (23456,))], [(2, (0,))]]
)
def test_public_mrt_never_invents_an_origin_from_sets_or_confederations(segments):
    (route,) = stream_mrt(io.BytesIO(_update(_attribute(2, _segments(segments)))))
    assert _signature(route) == segments
    assert not route.origin_known and route.origin_asn == 0


def test_public_mrt_reconstructs_as4_without_flattening_legacy_sets_or_confederations():
    legacy = [(3, (65000,)), (2, (64511,)), (1, (64500, 64501)), (2, (23456, 23456))]
    extended = [(3, (65002,)), (2, (4200000000, 4294967295))]
    attrs = _attribute(2, _segments(legacy, 2)) + _attribute(17, _segments(extended))
    (route,) = stream_mrt(io.BytesIO(_update(attrs, 2)))
    assert _signature(route) == legacy[:3] + extended[1:]
    assert route.as4_action == "reconstructed"
    assert route.as4_confederations_discarded
    assert route.origin_known and route.origin_asn == 4294967295


@pytest.mark.parametrize(
    "optional,action",
    [
        (b"\x02\x00", "ignored_malformed"),
        (_segments([(2, (4200000000, 4294967295, 64500))]), "ignored_longer_than_legacy"),
    ],
)
def test_public_mrt_retains_legacy_path_when_optional_as4_cannot_be_used(optional, action):
    legacy = [(2, (64511, 23456))]
    attrs = _attribute(2, _segments(legacy, 2)) + _attribute(17, optional)
    (route,) = stream_mrt(io.BytesIO(_update(attrs, 2)))
    assert _signature(route) == legacy and route.as4_action == action


def test_public_mrt_ignores_as4_on_four_octet_sessions_and_old_aggregation():
    legacy = [(2, (64511, 23456))]
    extended = _attribute(17, _segments([(2, (4294967295,))]))
    attrs = _attribute(2, _segments(legacy)) + extended
    (route,) = stream_mrt(io.BytesIO(_update(attrs)))
    assert _signature(route) == legacy and route.as4_action == "ignored_four_octet_session"
    attrs = _attribute(2, _segments(legacy, 2)) + extended
    attrs += _attribute(7, (64511).to_bytes(2, "big") + bytes(4))
    attrs += _attribute(18, (4200000000).to_bytes(4, "big") + bytes(4))
    (route,) = stream_mrt(io.BytesIO(_update(attrs, 2)))
    assert _signature(route) == legacy and route.as4_action == "ignored_legacy_aggregation"


@pytest.mark.parametrize("bad", [b"\x05\x01\x00\x00\x00\x01", b"\x02\x00", b"\x02\x01\x01"])
def test_public_mrt_rejects_whole_malformed_mandatory_path_and_keeps_next_record(bad):
    good = _update(_attribute(2, _segments([(2, (64496,))])))
    routes = list(stream_mrt(io.BytesIO(_update(_attribute(2, bad)) + good)))
    assert len(routes) == 1 and routes[0].as_path == [64496]


def test_public_mrt_validates_all_attributes_before_returning_path():
    path = _attribute(2, _segments([(2, (64496,))]))
    for attrs in [path + path, path + b"\x40\x03\x04\x01", b""]:
        assert list(stream_mrt(io.BytesIO(_update(attrs)))) == []


def test_public_ris_keeps_sets_unknown_origin_and_monitor_baseline():
    (route,) = parse_ris_message(_ris([64511, 64511, [64496, 4294967295]]))
    assert _signature(route) == [(2, (64511, 64511)), (1, (64496, 4294967295))]
    assert not route.origin_known and route.origin_asn == 0
    monitor = PrefixMonitor(
        AnalyzerConfig.from_dict(
            {
                "tenant_id": "owned-lane",
                "monitored_prefixes": [
                    {
                        "prefix": "192.0.2.0/24",
                        "expected_origins": [64496],
                    }
                ],
            }
        )
    )
    assert monitor.observe(route) == []
    (known,) = parse_ris_message(_ris([64511, 64496]))
    assert known.origin_known and monitor.observe(known) == []


def test_public_monitor_never_claims_confederation_or_set_members_as_ordered_transit():
    segments = [(3, (65000,)), (1, (64500, 64501)), (2, (64511, 64496)), (4, (65002,))]
    (route,) = stream_mrt(io.BytesIO(_update(_attribute(2, _segments(segments)))))
    monitor = PrefixMonitor(
        AnalyzerConfig.from_dict(
            {
                "tenant_id": "owned-lane",
                "monitored_prefixes": [
                    {
                        "prefix": "192.0.2.0/24",
                        "expected_origins": [64496],
                        "no_transit": [65000, 64500, 65002, 64496],
                    }
                ],
            }
        )
    )
    assert route.origin_known and route.origin_asn == 64496
    assert route.transit_asns == [64511]
    assert monitor.observe(route) == []


@pytest.mark.parametrize("path", [[64500.5], [True], [[None]], [[]]])
def test_public_ris_rejects_invented_or_empty_segment_values(path):
    assert parse_ris_message(_ris(path)) == []


def test_public_ris_keeps_complete_long_paths_and_charges_all_prefix_copies():
    path = [64511] * 65_537 + [4294967295]
    message = _ris(path)
    message["data"]["announcements"][0]["prefixes"].append("2001:db8::/32")
    routes = parse_ris_message(message)
    assert len(routes) == 2
    for route in routes:
        assert route.as_path == path
        assert _signature(route) == [(2, tuple(path))]
        assert route.origin_known and route.origin_asn == 4294967295
    routes[0].as_path[0] = 1
    assert routes[1].as_path == path
    assert parse_ris_message(message, memory_bytes=4096) == []
    message = _ris([64511, 64496])
    message["data"]["announcements"][0]["prefixes"] *= 20
    assert parse_ris_message(message, memory_bytes=4096) == []  # no accepted prefix leaks out


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "4096", None])
def test_public_ris_requires_finite_integer_workspace_configuration(bad):
    with pytest.raises(ValueError, match="ris_message_memory_bytes"):
        AnalyzerConfig.from_dict({"tenant_id": "owned-lane", "ris_message_memory_bytes": bad})


def test_public_ris_configured_workspace_reaches_replay_live_and_complete_output(
    tmp_path, monkeypatch
):
    path = [64511] * 65_537 + [4294967295]
    raw = json.dumps(_ris(path))
    replay = tmp_path / "capture.jsonl"
    replay.write_text(raw + "\n")
    monkeypatch.setattr(RISLiveClient, "messages", lambda self: iter([raw]))
    config = tmp_path / "config.json"
    for memory in (4096, 64 << 20):
        config.write_text(
            json.dumps(
                {
                    "tenant_id": "owned-lane",
                    "ris_message_memory_bytes": memory,
                    "monitored_prefixes": [{"prefix": "192.0.2.0/24", "expected_origins": [64496]}],
                }
            )
        )
        for source in (["--replay", str(replay)], ["--ris-live"]):
            output = tmp_path / "events.jsonl"
            assert main(["--config", str(config), "--out", str(output), *source]) == 0
            events = [json.loads(line) for line in output.read_text().splitlines()]
            if memory == 4096:
                assert events == []
            else:
                assert len(events) == 1
                assert events[0]["tenant_id"] == "owned-lane"
                assert events[0]["new_as_path"] == path
                assert events[0]["new_origin_asn"] == 4294967295


def test_public_mrt_keeps_whole_dual_family_withdrawals_before_announcements():
    attrs = _attribute(2, _segments([(2, (64511, 4294967295))]))
    reach = b"\x00\x02\x01\x10" + ipaddress.ip_address("2001:db8::1").packed
    attrs += _attribute(14, reach + b"\x00\x20\x20\x01\x0d\xb8")
    attrs += _attribute(15, b"\x00\x02\x01\x20\x20\x01\x0d\xb9")
    changes = list(
        stream_mrt(
            io.BytesIO(_update(attrs, withdrawals=b"\x18\xc0\x00\x02", nlri=b"\x18\xc6\x33\x64"))
        )
    )
    assert [row.prefix for row in changes] == [
        "192.0.2.0/24",
        "2001:db9::/32",
        "2001:db8::/32",
        "198.51.100.0/24",
    ]
    assert [row.kind for row in changes] == ["withdraw", "withdraw", "announce", "announce"]
    assert all(row.peer_asn == 64511 and row.peer_address == "192.0.2.1" for row in changes)
    assert all(row.event_time_unix_nano == 1700000000 * 1_000_000_000 for row in changes)
    assert all(not row.origin_known and row.as_path == [] for row in changes[:2])
    assert all(row.origin_asn == 4294967295 for row in changes[2:])


def test_public_mrt_keeps_withdrawal_only_update_without_inventing_a_path():
    attrs = _attribute(15, b"\x00\x02\x01\x20\x20\x01\x0d\xb9")
    changes = list(
        stream_mrt(io.BytesIO(_update(attrs, withdrawals=b"\x18\xc0\x00\x02", nlri=b"")))
    )
    assert [row.prefix for row in changes] == ["192.0.2.0/24", "2001:db9::/32"]
    assert all(
        row.kind == "withdraw"
        and not row.origin_known
        and row.origin_asn == 0
        and row.as_path_segments == ()
        for row in changes
    )


@pytest.mark.parametrize(
    "withdrawals,optional",
    [
        (b"\x18\xc0\x00\x02\x20\xc0", b""),
        (b"\x18\xc0\x00\x02", _attribute(15, b"\x00\x02\x01\x80\x20")),
        (b"", _attribute(15, b"\x00\x03\x01\x00")),
        (b"", _attribute(15, b"\x00\x02\x01") * 2),
    ],
)
def test_public_mrt_never_exposes_partial_withdrawals_from_malformed_updates(withdrawals, optional):
    attrs = _attribute(2, _segments([(2, (64496,))])) + optional
    assert list(stream_mrt(io.BytesIO(_update(attrs, withdrawals=withdrawals)))) == []


def test_public_ris_keeps_every_withdrawal_and_announcement_under_whole_admission():
    withdrawals = [f"{ipaddress.IPv4Address(0xC0000000 + i)}/32" for i in range(5001)]
    announcements = [f"{ipaddress.IPv6Address('2001:db8::') + i}/128" for i in range(5001)]
    message = _ris([64511, 4294967295])
    message["data"]["withdrawals"] = withdrawals
    message["data"]["announcements"][0]["prefixes"] = announcements
    changes = parse_ris_message(message)
    assert len(changes) == 10002
    assert [row.prefix for row in changes] == withdrawals + announcements
    assert all(
        row.kind == "withdraw" and not row.origin_known and row.as_path_segments == ()
        for row in changes[:5001]
    )
    assert all(
        row.kind == "announce"
        and row.as_path == [64511, 4294967295]
        and row.origin_asn == 4294967295
        for row in changes[5001:]
    )
    assert parse_ris_message(message, memory_bytes=4096) == []


@pytest.mark.parametrize("withdrawals", [["192.0.2.0/24", "not-a-prefix"], "192.0.2.0/24", [True]])
def test_public_ris_rejects_whole_malformed_withdrawal_message(withdrawals):
    message = _ris([64496])
    message["data"]["withdrawals"] = withdrawals
    assert parse_ris_message(message) == []
