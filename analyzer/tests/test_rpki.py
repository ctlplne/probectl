"""RFC 6811 route-origin validation tests."""

from __future__ import annotations

from probectl_analyzer.events import RPKIStatus
from probectl_analyzer.rpki import VRPSet

VRP_JSON = """
{"roas": [
  {"prefix": "192.0.2.0/24", "maxLength": 24, "asn": "AS64496"},
  {"prefix": "203.0.113.0/24", "maxLength": 26, "asn": 64497}
]}
"""


def vrp() -> VRPSet:
    return VRPSet.from_json(VRP_JSON)


def test_valid_when_origin_and_length_match():
    assert vrp().validate("192.0.2.0/24", 64496) == RPKIStatus.VALID


def test_invalid_when_wrong_origin():
    assert vrp().validate("192.0.2.0/24", 64500) == RPKIStatus.INVALID


def test_invalid_when_more_specific_than_max_length():
    # 203.0.113.0/27 is covered by the /24 ROA but exceeds maxLength 26.
    assert vrp().validate("203.0.113.0/27", 64497) == RPKIStatus.INVALID


def test_valid_more_specific_within_max_length():
    assert vrp().validate("203.0.113.0/25", 64497) == RPKIStatus.VALID


def test_not_found_when_no_covering_roa():
    assert vrp().validate("198.51.100.0/24", 64496) == RPKIStatus.NOT_FOUND


def test_asn_parsing_accepts_as_prefix_and_int():
    assert len(vrp()) == 2
