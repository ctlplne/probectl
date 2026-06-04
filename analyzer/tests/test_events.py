"""BGPEvent JSON serialization — the analyzer↔bridge contract."""

from __future__ import annotations

import json

from probectl_analyzer.events import BGPEvent, EventType, RPKIStatus, Severity


def test_to_json_uses_snake_case_keys_and_lowercase_enums():
    event = BGPEvent(
        tenant_id="t1",
        event_type=EventType.ORIGIN_CHANGE,
        prefix="192.0.2.0/24",
        new_origin_asn=64500,
        old_origin_asn=64496,
        new_as_path=[64511, 64500],
        old_as_path=[64511, 64496],
        expected_origins=[64496],
        rpki_status=RPKIStatus.INVALID,
        severity=Severity.WARNING,
        confidence=0.7,
        collector="rrc00",
        peer_asn=64511,
        peer_address="192.0.2.1",
        message="origin changed",
    )
    d = json.loads(event.to_json())

    assert d["tenant_id"] == "t1"
    assert d["event_type"] == "origin_change"
    assert d["rpki_status"] == "invalid"
    assert d["severity"] == "warning"
    assert d["new_as_path"] == [64511, 64500]
    assert d["old_origin_asn"] == 64496
    # Every proto field is represented (the bridge unmarshals all of them).
    expected_keys = {
        "tenant_id",
        "event_type",
        "severity",
        "confidence",
        "prefix",
        "new_origin_asn",
        "old_origin_asn",
        "new_as_path",
        "old_as_path",
        "expected_origins",
        "rpki_status",
        "collector",
        "peer_asn",
        "peer_address",
        "message",
        "detected_at_unix_nano",
    }
    assert set(d.keys()) == expected_keys


def test_detected_at_defaults_to_now():
    event = BGPEvent(tenant_id="t1", event_type=EventType.RPKI_INVALID, prefix="192.0.2.0/24")
    assert event.detected_at_unix_nano > 0
