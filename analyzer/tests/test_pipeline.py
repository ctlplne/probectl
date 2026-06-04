"""End-to-end pipeline test — the S14 Done-when.

Monitoring a prefix detects a simulated origin change with old/new AS path and
the RPKI status, emitted to the sink (which the Go bridge republishes onto the
bus). Exercises ingestion (RIS Live replay) → monitor → RPKI → emit, plus the
streaming MRT path.
"""

from __future__ import annotations

import io
import json

from mrt_fixtures import peer_index_table, rib_ipv4

from probectl_analyzer.config import AnalyzerConfig
from probectl_analyzer.emit import ListSink
from probectl_analyzer.events import EventType, RPKIStatus
from probectl_analyzer.pipeline import Analyzer
from probectl_analyzer.rpki import VRPSet

CONFIG = {
    "tenant_id": "t1",
    "collector": "rrc00",
    "monitored_prefixes": [{"prefix": "192.0.2.0/24", "expected_origins": [64496]}],
}

# A ROA that makes the legitimate origin (64496) valid and any other invalid.
VRP = VRPSet.from_dicts([{"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 64496}])


def _ris(path, prefix="192.0.2.0/24"):
    return json.dumps(
        {
            "type": "ris_message",
            "data": {
                "type": "UPDATE",
                "peer": "192.0.2.1",
                "peer_asn": "64511",
                "host": "rrc00",
                "path": path,
                "announcements": [{"next_hop": "192.0.2.1", "prefixes": [prefix]}],
            },
        }
    )


def test_origin_change_detected_with_paths_and_rpki_via_ris_replay():
    sink = ListSink()
    analyzer = Analyzer(AnalyzerConfig.from_dict(CONFIG), sink, VRP)

    # Baseline: legitimate origin 64496; then a hijacking origin 64500.
    replay = [_ris([64511, 64496]), _ris([64511, 64500])]
    count = analyzer.process_ris_replay(replay)

    assert count >= 1
    changes = [e for e in sink.events if e.event_type == EventType.ORIGIN_CHANGE]
    assert len(changes) == 1
    change = changes[0]
    assert change.tenant_id == "t1"
    assert change.old_origin_asn == 64496
    assert change.new_origin_asn == 64500
    assert change.old_as_path == [64511, 64496]
    assert change.new_as_path == [64511, 64500]
    assert change.rpki_status == RPKIStatus.INVALID  # the new origin is RPKI-invalid

    # The unexpected origin also raises a hijack signal.
    assert any(e.event_type == EventType.POSSIBLE_HIJACK for e in sink.events)


def test_pipeline_streams_mrt_dump():
    sink = ListSink()
    analyzer = Analyzer(AnalyzerConfig.from_dict(CONFIG), sink, VRP)

    dump = (
        peer_index_table(peer_as=64511, peer_ip="192.0.2.1")
        + rib_ipv4("192.0.2.0/24", [64511, 64496])  # baseline (valid)
        + rib_ipv4("192.0.2.0/24", [64511, 64500])  # origin change (invalid)
    )
    analyzer.process_mrt(io.BytesIO(dump))

    assert any(e.event_type == EventType.ORIGIN_CHANGE for e in sink.events)
    invalid = [e for e in sink.events if e.event_type == EventType.RPKI_INVALID]
    assert invalid and invalid[0].new_origin_asn == 64500
