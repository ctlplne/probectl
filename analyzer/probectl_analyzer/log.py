# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

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


def get_logger(name: str = "probectl.analyzer") -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    return structlog.get_logger(name)
