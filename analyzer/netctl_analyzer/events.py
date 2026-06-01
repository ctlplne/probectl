"""The ``netctl.bgp.events`` schema (S14).

A ``BGPEvent`` is a routing-security *signal* (not ground truth): every event
carries a confidence and a severity and is tunable/suppressible downstream
(CLAUDE.md §7 guardrail 9). The JSON form (snake_case keys, lowercase enum
values) is the analyzer↔control-plane contract that ``internal/bgp`` translates
into the canonical ``netctl.bgp.v1.BGPEvent`` protobuf bus message.
"""

from __future__ import annotations

import enum
import json
import time
from dataclasses import asdict, dataclass, field


class EventType(enum.StrEnum):
    ORIGIN_CHANGE = "origin_change"
    POSSIBLE_HIJACK = "possible_hijack"
    POSSIBLE_LEAK = "possible_leak"
    RPKI_INVALID = "rpki_invalid"


class RPKIStatus(enum.StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"


class Severity(enum.StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class BGPEvent:
    """One routing observation about a monitored prefix."""

    tenant_id: str
    event_type: EventType
    prefix: str
    new_origin_asn: int = 0
    old_origin_asn: int = 0
    new_as_path: list[int] = field(default_factory=list)
    old_as_path: list[int] = field(default_factory=list)
    expected_origins: list[int] = field(default_factory=list)
    rpki_status: RPKIStatus = RPKIStatus.UNKNOWN
    severity: Severity = Severity.INFO
    confidence: float = 0.5
    collector: str = ""
    peer_asn: int = 0
    peer_address: str = ""
    message: str = ""
    detected_at_unix_nano: int = 0

    def __post_init__(self) -> None:
        if self.detected_at_unix_nano == 0:
            self.detected_at_unix_nano = time.time_ns()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["rpki_status"] = self.rpki_status.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)
