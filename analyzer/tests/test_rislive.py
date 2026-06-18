"""RIS Live parsing + replay tests (no network)."""

from __future__ import annotations

import json

import pytest

from probectl_analyzer.rislive import (
    MAX_RIS_PATH_HOPS,
    MAX_RIS_PREFIXES,
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


def test_ris_message_cardinality_limits_are_enforced():
    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"]["path"] = list(range(MAX_RIS_PATH_HOPS + 1))
    assert parse_ris_message(msg) == []

    msg = json.loads(json.dumps(RIS_MESSAGE))
    msg["data"]["announcements"] = [
        {"prefixes": [f"192.0.2.{i % 255}/32" for i in range(MAX_RIS_PREFIXES + 1)]}
    ]
    assert parse_ris_message(msg) == []
