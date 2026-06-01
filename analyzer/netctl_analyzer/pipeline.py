"""Wires ingestion (MRT / RIS Live) → per-prefix monitoring → event emission."""

from __future__ import annotations

import ssl
import urllib.request
from collections.abc import Iterable
from typing import BinaryIO

from .config import AnalyzerConfig
from .emit import EventSink
from .log import get_logger
from .monitor import PrefixMonitor
from .mrt import BGPRoute, stream_mrt
from .rislive import iter_updates
from .rpki import VRPSet

_log = get_logger("netctl.analyzer.pipeline")


def load_vrp(config: AnalyzerConfig) -> VRPSet | None:
    """Load the RPKI VRP set from a file or (optionally) a validator URL.

    A missing/unreachable source degrades to ``None`` (→ RPKI ``unknown``) rather
    than breaking analysis (CLAUDE.md §7 guardrail 10). The URL fetch validates
    TLS certificates (guardrail 12) and treats the response as untrusted.
    """
    if config.rpki_vrp_file:
        return VRPSet.from_file(config.rpki_vrp_file)
    if config.rpki_vrp_url:
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(
                config.rpki_vrp_url, headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                return VRPSet.from_json(resp.read().decode("utf-8"))
        except Exception as err:  # degrade gracefully on any fetch/parse failure
            _log.warning("RPKI VRP fetch failed; degrading to unknown", error=str(err))
            return None
    return None


class Analyzer:
    """Feeds observed routes through the monitor and emits the resulting events."""

    def __init__(self, config: AnalyzerConfig, sink: EventSink, vrp: VRPSet | None = None):
        self._config = config
        self._sink = sink
        self._monitor = PrefixMonitor(config, vrp)
        self._log = get_logger("netctl.analyzer")

    def process_routes(self, routes: Iterable[BGPRoute]) -> int:
        count = 0
        for route in routes:
            for event in self._monitor.observe(route):
                self._sink.emit(event)
                count += 1
                self._log.info(
                    "bgp event",
                    event_type=event.event_type.value,
                    prefix=event.prefix,
                    severity=event.severity.value,
                    rpki=event.rpki_status.value,
                )
        return count

    def process_mrt(self, fp: BinaryIO) -> int:
        return self.process_routes(stream_mrt(fp))

    def process_ris_replay(self, lines: Iterable[str]) -> int:
        return self.process_routes(iter_updates(lines))
