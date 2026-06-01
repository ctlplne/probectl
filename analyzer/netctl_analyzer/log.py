"""structlog configuration for the analyzer (CLAUDE.md §6 — no ``print``)."""

from __future__ import annotations

import logging

import structlog


def configure(level: str = "INFO") -> None:
    """Configure structlog to emit JSON lines on stderr at the given level."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(file=__import__("sys").stderr),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str = "netctl.analyzer") -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
