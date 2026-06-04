"""probectl BGP analyzer.

Ingests public BGP collector data (RouteViews MRT, RIPE RIS / RIS Live),
performs per-prefix AS-path monitoring with origin-change / hijack / leak
detection and RPKI (RFC 6811) validation status, and emits ``probectl.bgp.events``
as JSON Lines. The Go control plane consumes them via the ``internal/bgp``
bridge, which republishes each event onto the bus as the canonical
``probectl.bgp.v1.BGPEvent`` protobuf (S14).

Logging uses ``structlog``; MRT dumps are stream-processed (never loaded whole).
"""

from __future__ import annotations

from .config import AnalyzerConfig, MonitoredPrefix
from .events import BGPEvent, EventType, RPKIStatus, Severity
from .monitor import PrefixMonitor
from .mrt import BGPRoute, stream_mrt
from .pipeline import Analyzer, load_vrp
from .rislive import iter_updates, parse_ris_message
from .rpki import ROA, VRPSet

__version__ = "0.1.0.dev0"

__all__ = [
    "AnalyzerConfig",
    "MonitoredPrefix",
    "BGPEvent",
    "EventType",
    "RPKIStatus",
    "Severity",
    "PrefixMonitor",
    "BGPRoute",
    "stream_mrt",
    "Analyzer",
    "load_vrp",
    "iter_updates",
    "parse_ris_message",
    "ROA",
    "VRPSet",
    "__version__",
]
