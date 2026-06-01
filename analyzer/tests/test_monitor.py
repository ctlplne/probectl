"""Per-prefix detection tests: origin change, hijack, leak, RPKI."""

from __future__ import annotations

from netctl_analyzer.config import AnalyzerConfig
from netctl_analyzer.events import EventType, RPKIStatus, Severity
from netctl_analyzer.monitor import PrefixMonitor
from netctl_analyzer.mrt import BGPRoute
from netctl_analyzer.rpki import VRPSet


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
