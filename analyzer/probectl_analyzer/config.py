# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Analyzer configuration: which prefixes to monitor, for which origins, plus
the collector identity and RPKI source. Loaded from JSON (no YAML dependency).

Tenancy: a config belongs to exactly one ``tenant_id``; the emitted events carry
it, and the Go bridge fails closed on an event with no tenant (F50).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field


@dataclass
class MonitoredPrefix:
    prefix: str
    expected_origins: list[int] = field(default_factory=list)
    # ASNs that must never appear as transit for this prefix (route-leak heuristic).
    no_transit: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Validate/normalize the prefix early (untrusted config is still input).
        self.network = ipaddress.ip_network(self.prefix, strict=False)
        self.prefix = str(self.network)


@dataclass
class AnalyzerConfig:
    tenant_id: str
    monitored_prefixes: list[MonitoredPrefix] = field(default_factory=list)
    collector: str = ""
    rpki_vrp_file: str | None = None
    rpki_vrp_url: str | None = None
    log_level: str = "INFO"
    # DPR-056: a routing anomaly is re-announced by every collector peer on
    # every update; one event per (prefix, kind, origin) per window keeps the
    # tenant's event surface and the bus readable. 0 disables suppression.
    event_suppression_seconds: float = 300.0

    @classmethod
    def from_dict(cls, d: dict) -> AnalyzerConfig:
        if not d.get("tenant_id"):
            raise ValueError("config: tenant_id is required (tenant is the outermost scope)")
        suppression = float(d.get("event_suppression_seconds", 300))
        if suppression < 0:
            raise ValueError("config: event_suppression_seconds must be >= 0")
        prefixes = [
            MonitoredPrefix(
                prefix=p["prefix"],
                expected_origins=[int(a) for a in p.get("expected_origins", [])],
                no_transit=[int(a) for a in p.get("no_transit", [])],
            )
            for p in d.get("monitored_prefixes", [])
        ]
        return cls(
            tenant_id=str(d["tenant_id"]),
            monitored_prefixes=prefixes,
            collector=str(d.get("collector", "")),
            rpki_vrp_file=d.get("rpki_vrp_file"),
            rpki_vrp_url=d.get("rpki_vrp_url"),
            log_level=str(d.get("log_level", "INFO")),
            event_suppression_seconds=suppression,
        )

    @classmethod
    def from_file(cls, path: str) -> AnalyzerConfig:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
