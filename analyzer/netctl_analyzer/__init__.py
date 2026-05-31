"""netctl BGP analyzer.

Ingests public BGP collector data (RouteViews MRT, RIPE RIS / RIS Live),
performs per-prefix AS-path monitoring and origin/hijack/leak detection with
RPKI validation status, and emits ``netctl.bgp.events`` consumed by the Go
control plane via ``internal/bgp``.

S0 scaffold: this package is an intentional placeholder so the analyzer's
tooling (ruff, black, pytest) and CI jobs exist from day one. The analyzer
itself is implemented in S14, using ``structlog`` for structured logging.
"""

__version__ = "0.0.0.dev0"
