"""RPKI route-origin validation (RFC 6811) against a VRP set.

A *VRP* (Validated ROA Payload) is ``(prefix, max_length, asn)``. The analyzer
loads VRPs from a validator export (the ``rpki-client`` / Routinator JSON
format) and checks each announcement offline — the "run a validator, check
ROAs" of S14, with the network fetch kept optional so a down validator degrades
to ``unknown`` rather than breaking analysis (CLAUDE.md §7 guardrail 10).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

from .events import RPKIStatus

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _parse_asn(value: object) -> int:
    """Accept 13335, "13335", or "AS13335"."""
    if isinstance(value, int):
        return value
    s = str(value).upper().removeprefix("AS").strip()
    return int(s)


@dataclass(frozen=True)
class ROA:
    network: IPNetwork
    max_length: int
    asn: int


class VRPSet:
    """A set of validated ROA payloads supporting RFC 6811 origin validation."""

    def __init__(self, roas: list[ROA]):
        self._roas = list(roas)

    def __len__(self) -> int:
        return len(self._roas)

    @classmethod
    def from_dicts(cls, roas: list[dict]) -> VRPSet:
        out: list[ROA] = []
        for r in roas:
            net = ipaddress.ip_network(r["prefix"], strict=False)
            max_len = int(r.get("maxLength", r.get("max_length", net.prefixlen)))
            out.append(ROA(network=net, max_length=max_len, asn=_parse_asn(r["asn"])))
        return cls(out)

    @classmethod
    def from_json(cls, text: str) -> VRPSet:
        data = json.loads(text)
        roas = data["roas"] if isinstance(data, dict) else data
        return cls.from_dicts(roas)

    @classmethod
    def from_file(cls, path: str) -> VRPSet:
        with open(path, encoding="utf-8") as fh:
            return cls.from_json(fh.read())

    def validate(self, prefix: str, origin_asn: int) -> RPKIStatus:
        """Return the RFC 6811 validation state for an (prefix, origin) pair."""
        try:
            ann = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return RPKIStatus.UNKNOWN

        covering = [
            r for r in self._roas if r.network.version == ann.version and _covers(r.network, ann)
        ]
        if not covering:
            return RPKIStatus.NOT_FOUND
        for r in covering:
            if r.asn == origin_asn and ann.prefixlen <= r.max_length:
                return RPKIStatus.VALID
        return RPKIStatus.INVALID


def _covers(roa_net: IPNetwork, ann: IPNetwork) -> bool:
    """True when the ROA prefix is equal-or-less-specific than the announcement
    (i.e. the announced prefix falls within the ROA prefix)."""
    if ann.prefixlen < roa_net.prefixlen:
        return False
    return ann.subnet_of(roa_net)  # type: ignore[arg-type]
