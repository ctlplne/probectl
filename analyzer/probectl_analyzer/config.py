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

    @classmethod
    def from_dict(cls, d: dict) -> AnalyzerConfig:
        if not d.get("tenant_id"):
            raise ValueError("config: tenant_id is required (tenant is the outermost scope)")
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
        )

    @classmethod
    def from_file(cls, path: str) -> AnalyzerConfig:
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))
