# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Per-prefix detection tests: origin change, hijack, leak, RPKI."""

from __future__ import annotations

from probectl_analyzer.config import AnalyzerConfig
from probectl_analyzer.events import EventType, RPKIStatus, Severity
from probectl_analyzer.monitor import PrefixMonitor
from probectl_analyzer.mrt import BGPRoute
from probectl_analyzer.rpki import VRPSet


def make_monitor(no_transit=None, vrp=None) -> PrefixMonitor:
    config = AnalyzerConfig.from_dict(
        {
            "tenant_id": "t1",
            "collector": "rrc00",
            "monitored_prefixes": [
                {
                    "prefix": "192.0.2.0/24",
                    "expected_origins": [64496],
                    "no_transit": no_transit or [],
                }
            ],
        }
    )
    return PrefixMonitor(config, vrp)


def test_unmonitored_prefix_yields_nothing():
    mon = make_monitor()
    assert mon.observe(BGPRoute(prefix="10.0.0.0/8", as_path=[64496])) == []


def test_detects_origin_change_with_old_and_new_path():
    mon = make_monitor()
    # Baseline sighting — no event.
    assert mon.observe(BGPRoute(prefix="192.0.2.0/24", as_path=[64511, 64496])) == []
    # Origin flips 64496 -> 64496-different.
    events = mon.observe(BGPRoute(prefix="192.0.2.0/24", as_path=[64511, 64498]))
    change = [e for e in events if e.event_type == EventType.ORIGIN_CHANGE]
    assert len(change) == 1
    e = change[0]
    assert e.old_origin_asn == 64496
    assert e.new_origin_asn == 64498
    assert e.old_as_path == [64511, 64496]
    assert e.new_as_path == [64511, 64498]
    assert e.tenant_id == "t1"
    assert e.collector == "rrc00"


def test_detects_possible_hijack_by_unexpected_origin():
    mon = make_monitor()
    events = mon.observe(BGPRoute(prefix="192.0.2.0/24", as_path=[64511, 64502]))
    hijack = [e for e in events if e.event_type == EventType.POSSIBLE_HIJACK]
    assert len(hijack) == 1
    assert hijack[0].severity == Severity.CRITICAL
    assert hijack[0].new_origin_asn == 64502


def test_subprefix_hijack_is_higher_confidence():
    mon = make_monitor()
    events = mon.observe(BGPRoute(prefix="192.0.2.128/25", as_path=[64511, 64502]))
    hijack = [e for e in events if e.event_type == EventType.POSSIBLE_HIJACK]
    assert hijack and hijack[0].confidence >= 0.9


def test_detects_route_leak_via_no_transit_as():
    mon = make_monitor(no_transit=[64666])
    events = mon.observe(BGPRoute(prefix="192.0.2.0/24", as_path=[64511, 64666, 64496]))
    leaks = [e for e in events if e.event_type == EventType.POSSIBLE_LEAK]
    assert len(leaks) == 1
    assert leaks[0].severity == Severity.WARNING


def test_rpki_invalid_emits_event_and_attaches_status():
    vrp = VRPSet.from_dicts([{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 64496}])
    mon = make_monitor(vrp=vrp)
    events = mon.observe(BGPRoute(prefix="192.0.2.0/24", as_path=[64511, 64502]))
    assert any(e.event_type == EventType.RPKI_INVALID for e in events)
    assert all(e.rpki_status == RPKIStatus.INVALID for e in events)


# DPR-056: a real anomaly is re-announced by every collector peer on every
# update; the monitor emits one event per (prefix, kind, origin) per window.
def make_suppressing_monitor(seconds: float) -> PrefixMonitor:
    config = AnalyzerConfig.from_dict(
        {
            "tenant_id": "t1",
            "event_suppression_seconds": seconds,
            "monitored_prefixes": [
                {"prefix": "192.0.2.0/24", "expected_origins": [64496], "no_transit": [64666]}
            ],
        }
    )
    return PrefixMonitor(config)


def hijack(peer: int, t_s: float, origin: int = 64500) -> BGPRoute:
    return BGPRoute(
        prefix="192.0.2.0/24", as_path=[peer, origin], event_time_unix_nano=int(t_s * 1e9)
    )


def test_repeat_announcements_are_suppressed_within_the_window():
    mon = make_suppressing_monitor(300)
    first = mon.observe(hijack(64511, 1000))
    assert [e.event_type for e in first] == [EventType.POSSIBLE_HIJACK]
    # Other peers re-announce the same anomaly seconds later: suppressed.
    assert mon.observe(hijack(64512, 1001)) == []
    assert mon.observe(hijack(64513, 1299)) == []
    assert mon.suppressed == 2
    # After the window it is worth another event.
    assert [e.event_type for e in mon.observe(hijack(64514, 1300))] == [EventType.POSSIBLE_HIJACK]


def test_a_different_origin_is_a_different_anomaly():
    mon = make_suppressing_monitor(300)
    assert len(mon.observe(hijack(64511, 1000, origin=64500))) == 1
    events = mon.observe(hijack(64511, 1001, origin=64501))
    # origin_change (64500 -> 64501) plus a hijack by the new unexpected origin.
    assert sorted(e.event_type for e in events) == sorted(
        [EventType.ORIGIN_CHANGE, EventType.POSSIBLE_HIJACK]
    )
    assert mon.observe(hijack(64512, 1002, origin=64501)) == []


def test_suppression_can_be_disabled():
    mon = make_suppressing_monitor(0)
    assert len(mon.observe(hijack(64511, 1000))) == 1
    assert len(mon.observe(hijack(64512, 1001))) == 1
    assert mon.suppressed == 0


def test_leak_suppression_keys_on_the_leaking_ases():
    mon = make_suppressing_monitor(300)
    leak = BGPRoute(
        prefix="192.0.2.0/24", as_path=[64511, 64666, 64496], event_time_unix_nano=10**12
    )
    assert [e.event_type for e in mon.observe(leak)] == [EventType.POSSIBLE_LEAK]
    again = BGPRoute(
        prefix="192.0.2.0/24", as_path=[64512, 64666, 64496], event_time_unix_nano=10**12 + 10**9
    )
    assert mon.observe(again) == []


def test_rejects_negative_suppression_window():
    import pytest

    with pytest.raises(ValueError):
        AnalyzerConfig.from_dict({"tenant_id": "t1", "event_suppression_seconds": -1})
