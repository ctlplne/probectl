# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Wires ingestion (MRT / RIS Live) → per-prefix monitoring → event emission."""

from __future__ import annotations

import ssl
import time
import urllib.request
from collections.abc import Iterable
from typing import BinaryIO

from .config import AnalyzerConfig
from .emit import EventSink
from .log import get_logger
from .monitor import PrefixMonitor
from .mrt import BGPRoute, stream_mrt
from .rislive import iter_updates
from .rpki import VRPSet, overlapping

_log = get_logger("probectl.analyzer.pipeline")


def load_vrp(config: AnalyzerConfig) -> VRPSet | None:
    """Load the RPKI VRP set from a file or (optionally) a validator URL.

    A missing/unreachable source degrades to ``None`` (→ RPKI ``unknown``) rather
    than breaking analysis (CLAUDE.md §7 guardrail 10). The URL fetch validates
    TLS certificates (guardrail 12) and treats the response as untrusted. The
    export is streamed and reduced to the ROAs that overlap the monitored
    prefixes as it arrives (DPR-055): a full validator export (~100 MB, 600k
    ROAs) used to be materialized whole and OOM-killed the sidecar.
    """
    source = config.rpki_vrp_file or config.rpki_vrp_url
    if not source:
        return None
    keep = overlapping(p.prefix for p in config.monitored_prefixes)
    started = time.monotonic()
    _log.info(
        "loading RPKI VRP export",
        source=source,
        monitored_prefixes=len(config.monitored_prefixes),
    )
    try:
        if config.rpki_vrp_file:
            vrp = VRPSet.from_file(config.rpki_vrp_file, keep=keep)
        else:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(source, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                vrp = VRPSet.from_stream(resp, keep=keep)
    except Exception as err:  # degrade gracefully on any fetch/parse failure
        _log.warning("RPKI VRP load failed; degrading to unknown", source=source, error=str(err))
        return None
    _log.info(
        "RPKI VRP export loaded",
        source=source,
        roas_scanned=vrp.scanned,
        roas_kept=len(vrp),
        seconds=round(time.monotonic() - started, 1),
    )
    return vrp


class Analyzer:
    """Feeds observed routes through the monitor and emits the resulting events."""

    def __init__(self, config: AnalyzerConfig, sink: EventSink, vrp: VRPSet | None = None):
        self._config = config
        self._sink = sink
        self._monitor = PrefixMonitor(config, vrp)
        self._log = get_logger("probectl.analyzer")

    @property
    def suppressed(self) -> int:
        """Repeat anomalies dropped by the suppression window (DPR-056)."""
        return self._monitor.suppressed

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
