"""Per-prefix AS-path monitoring and origin/hijack/leak detection.

Detections are *signals*, not verdicts (CLAUDE.md §7 guardrail 9): each carries a
confidence in [0, 1] and a severity, and the rules are deliberately simple and
tunable. The monitor is fed normalized :class:`BGPRoute` observations from either
the MRT parser or RIS Live, so the source is irrelevant to detection.
"""

from __future__ import annotations

import ipaddress

from .config import AnalyzerConfig, MonitoredPrefix
from .events import BGPEvent, EventType, RPKIStatus, Severity
from .mrt import BGPRoute
from .rpki import VRPSet

_Net = ipaddress.IPv4Network | ipaddress.IPv6Network


class PrefixMonitor:
    """Tracks the origin/path baseline per observed prefix and emits events when a
    monitored prefix (or a more-specific of one) deviates."""

    def __init__(self, config: AnalyzerConfig, vrp: VRPSet | None = None):
        self._config = config
        self._vrp = vrp
        self._monitored: list[tuple[_Net, MonitoredPrefix]] = [
            (mp.network, mp) for mp in config.monitored_prefixes
        ]
        self._origin: dict[str, int] = {}
        self._path: dict[str, list[int]] = {}

    def _match(self, prefix: str) -> MonitoredPrefix | None:
        """Return the most-specific monitored prefix that covers ``prefix``."""
        try:
            net = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return None
        best: MonitoredPrefix | None = None
        best_len = -1
        for mon_net, mp in self._monitored:
            if mon_net.version != net.version:
                continue
            if net.prefixlen >= mon_net.prefixlen and net.subnet_of(mon_net):  # type: ignore[arg-type]
                if mon_net.prefixlen > best_len:
                    best, best_len = mp, mon_net.prefixlen
        return best

    def observe(self, route: BGPRoute) -> list[BGPEvent]:
        mp = self._match(route.prefix)
        if mp is None:
            return []

        origin = route.origin_asn
        path = list(route.as_path)
        rpki = self._vrp.validate(route.prefix, origin) if self._vrp else RPKIStatus.UNKNOWN
        exact = ipaddress.ip_network(route.prefix, strict=False) == mp.network
        expected = set(mp.expected_origins)

        events: list[BGPEvent] = []
        prior = self._origin.get(route.prefix)
        prior_path = self._path.get(route.prefix, [])

        # Origin change: the origin AS for this prefix differs from the last sighting.
        if prior is not None and prior != origin:
            events.append(
                self._event(
                    mp,
                    route,
                    EventType.ORIGIN_CHANGE,
                    Severity.WARNING,
                    0.7,
                    rpki,
                    new_origin=origin,
                    old_origin=prior,
                    new_path=path,
                    old_path=prior_path,
                    message=f"origin for {route.prefix} changed AS{prior} -> AS{origin}",
                )
            )

        # Possible hijack: an origin outside the configured allow-list announced
        # this prefix (a more-specific is higher-confidence sub-prefix hijack).
        if expected and origin not in expected:
            events.append(
                self._event(
                    mp,
                    route,
                    EventType.POSSIBLE_HIJACK,
                    Severity.CRITICAL,
                    0.9 if not exact else 0.85,
                    rpki,
                    new_origin=origin,
                    new_path=path,
                    message=(
                        f"{'sub-prefix ' if not exact else ''}{route.prefix} announced by "
                        f"unexpected AS{origin} (expected {sorted(expected)})"
                    ),
                )
            )

        # Possible leak: an AS that must not transit this prefix appears mid-path.
        transit = set(path[:-1])
        leaked = sorted(transit.intersection(mp.no_transit))
        if leaked:
            events.append(
                self._event(
                    mp,
                    route,
                    EventType.POSSIBLE_LEAK,
                    Severity.WARNING,
                    0.6,
                    rpki,
                    new_origin=origin,
                    new_path=path,
                    message=f"{route.prefix} path transits no-transit AS {leaked}",
                )
            )

        # RPKI-invalid announcement (RFC 6811).
        if rpki == RPKIStatus.INVALID:
            events.append(
                self._event(
                    mp,
                    route,
                    EventType.RPKI_INVALID,
                    Severity.WARNING,
                    0.8,
                    rpki,
                    new_origin=origin,
                    new_path=path,
                    message=f"{route.prefix} from AS{origin} is RPKI-invalid",
                )
            )

        self._origin[route.prefix] = origin
        self._path[route.prefix] = path
        return events

    def _event(
        self,
        mp: MonitoredPrefix,
        route: BGPRoute,
        etype: EventType,
        severity: Severity,
        confidence: float,
        rpki: RPKIStatus,
        *,
        new_origin: int = 0,
        old_origin: int = 0,
        new_path: list[int] | None = None,
        old_path: list[int] | None = None,
        message: str = "",
    ) -> BGPEvent:
        return BGPEvent(
            tenant_id=self._config.tenant_id,
            event_type=etype,
            prefix=route.prefix,
            new_origin_asn=new_origin,
            old_origin_asn=old_origin,
            new_as_path=new_path or [],
            old_as_path=old_path or [],
            expected_origins=list(mp.expected_origins),
            rpki_status=rpki,
            severity=severity,
            confidence=confidence,
            collector=self._config.collector,
            peer_asn=route.peer_asn,
            peer_address=route.peer_address,
            message=message,
        )
