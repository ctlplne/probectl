# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""RIS Live parsing + replay tests (no network)."""

from __future__ import annotations

import json

import pytest

from probectl_analyzer.rislive import (
    iter_updates,
    parse_ris_message,
)

RIS_MESSAGE = {
    "type": "ris_message",
    "data": {
        "type": "UPDATE",
        "timestamp": 1700000000.0,
        "peer": "192.0.2.1",
        "peer_asn": "64511",
        "host": "rrc00",
        "path": [64511, 64500, 64496],
        "announcements": [
            {"next_hop": "192.0.2.1", "prefixes": ["192.0.2.0/24", "192.0.2.128/25"]}
        ],
        "withdrawals": [],
    },
}


def test_parse_ris_message_yields_one_route_per_prefix():
    routes = parse_ris_message(RIS_MESSAGE)
    assert [r.prefix for r in routes] == ["192.0.2.0/24", "192.0.2.128/25"]
    r = routes[0]
    assert r.as_path == [64511, 64500, 64496]
    assert r.origin_asn == 64496
    assert r.peer_asn == 64511
    assert r.peer_address == "192.0.2.1"
    assert r.event_time_unix_nano == 1_700_000_000_000_000_000
    assert r.collector == "rrc00"


def test_ris_source_clock_preserves_exact_wire_nanoseconds_without_float_rounding():
    for token, expected in (
        ("1700000000.123456789", 1_700_000_000_123_456_789),
        ("9223372036.854775807", 2**63 - 1),
        ("1.0000000009", 1_000_000_000),
        ("1e-10000", 0),
    ):
        raw = json.dumps(RIS_MESSAGE).replace("1700000000.0", token)
        routes = list(iter_updates([raw]))
        assert len(routes) == 2 and all(
            route.event_time_unix_nano == expected for route in routes
        ), "RIS source clock lost exact wire nanoseconds"


def test_ris_invalid_clock_and_json_numeric_depth_cannot_stop_the_next_message():
    good = json.dumps(RIS_MESSAGE)
    for token in ("Infinity", "1e10000", '"Infinity"', "9223372036.854775808", "-1"):
        bad = good.replace("1700000000.0", token)
        try:
            routes = list(iter_updates([bad, good]))
        except Exception as error:
            pytest.fail(
                "invalid RIS source clock escaped whole-message refusal: " + type(error).__name__
            )
        assert len(routes) == 2 and all(
            route.event_time_unix_nano == 1_700_000_000_000_000_000 for route in routes
        ), "invalid RIS source clock published a partial or out-of-range message"
    for bad in ("[" * 2000 + "]" * 2000, '{"data":' + "9" * 5000 + "}"):
        try:
            routes = list(iter_updates([bad, good]))
        except Exception as error:
            pytest.fail(
                "untrusted JSON numeric/depth input escaped source refusal: " + type(error).__name__
            )
        assert len(routes) == 2, "invalid source JSON lost its following valid message"


def test_oversized_ris_host_is_refused():
    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"]["host"] = "r" * 254
    assert parse_ris_message(msg) == []


def test_flattens_as_set_in_path():
    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"]["path"] = [64511, [64500, 64501]]  # AS_SET encoded as a sub-list
    routes = parse_ris_message(msg)
    assert routes[0].as_path == [64511, 64500, 64501]


def test_ignores_non_update_and_non_ris_messages():
    assert parse_ris_message({"type": "ris_error", "data": {}}) == []
    assert parse_ris_message({"type": "ris_message", "data": {"type": "KEEPALIVE"}}) == []


def test_iter_updates_replays_and_skips_malformed_lines():
    lines = [
        json.dumps(RIS_MESSAGE),
        "",  # blank
        "{not json",  # malformed → skipped
        json.dumps(
            {
                "type": "ris_message",
                "data": {
                    "type": "UPDATE",
                    "path": [64512],
                    "announcements": [{"prefixes": ["203.0.113.0/24"]}],
                },
            }
        ),
    ]
    routes = list(iter_updates(lines))
    assert [r.prefix for r in routes] == [
        "192.0.2.0/24",
        "192.0.2.128/25",
        "203.0.113.0/24",
    ]


@pytest.mark.parametrize(
    "patch",
    [
        {"path": "not-a-list"},
        {"path": [["not-asn"]]},
        {"peer_asn": "not-asn"},
        {"announcements": "not-a-list"},
        {"announcements": [{"prefixes": "not-a-list"}]},
        {"announcements": [{"prefixes": [True]}]},
    ],
)
def test_type_hostile_ris_messages_are_skipped(patch):
    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"].update(patch)

    assert parse_ris_message(msg) == []
    assert list(iter_updates([json.dumps(msg)])) == []


def test_ris_message_resource_and_prefix_admission_are_enforced():
    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"]["path"] = list(range(1025))
    assert parse_ris_message(msg, memory_bytes=4096) == []

    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"]["announcements"] = [{"prefixes": [f"192.0.2.{i % 255}/32" for i in range(4097)]}]
    assert parse_ris_message(msg, memory_bytes=4096) == []
