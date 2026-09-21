# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Stdlib-only MRT interop runner for `make interop-offline`.

The analyzer's normal test suite uses pytest and the packaged structlog
dependency. This runner intentionally avoids both so the offline interop gate can
run on a bare checkout and still exercise the real MRT parser.
"""

from __future__ import annotations

import importlib.util
import io
import sys
import types
from pathlib import Path


class _NoopLogger:
    def debug(self, *args: object, **kwargs: object) -> None:
        return None

    def info(self, *args: object, **kwargs: object) -> None:
        return None

    def warning(self, *args: object, **kwargs: object) -> None:
        return None

    def warn(self, *args: object, **kwargs: object) -> None:
        return None

    def error(self, *args: object, **kwargs: object) -> None:
        return None


def _install_structlog_stub() -> None:
    structlog = types.ModuleType("structlog")
    structlog.configure = lambda *args, **kwargs: None
    structlog.get_logger = lambda name=None: _NoopLogger()
    structlog.make_filtering_bound_logger = lambda level: _NoopLogger
    structlog.PrintLoggerFactory = lambda file=None: object()
    structlog.contextvars = types.SimpleNamespace(merge_contextvars=lambda *args, **kwargs: None)
    structlog.processors = types.SimpleNamespace(
        add_log_level=lambda *args, **kwargs: None,
        TimeStamper=lambda **kwargs: (lambda *args, **inner_kwargs: None),
        JSONRenderer=lambda **kwargs: (lambda *args, **inner_kwargs: None),
    )
    structlog.stdlib = types.SimpleNamespace(BoundLogger=_NoopLogger)
    sys.modules.setdefault("structlog", structlog)


def _load_module(name: str, path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    _install_structlog_stub()
    root = Path(__file__).resolve().parents[1]
    package = types.ModuleType("probectl_analyzer")
    package.__path__ = [str(root / "probectl_analyzer")]
    sys.modules.setdefault("probectl_analyzer", package)

    mrt = _load_module("probectl_analyzer.mrt", root / "probectl_analyzer" / "mrt.py")
    fixtures = _load_module("mrt_fixtures", Path(__file__).resolve().parent / "mrt_fixtures.py")

    data = (
        fixtures.peer_index_table(peer_as=64511, peer_ip="192.0.2.1")
        + fixtures.rib_ipv4("192.0.2.0/24", [64511, 64500, 64496], ts=1_777_000_900)
        + fixtures.bgp4mp_update_as4("198.51.100.0/24", [64511, 64502], ts=1_777_000_901)
    )
    routes = list(mrt.stream_mrt(io.BytesIO(data)))
    assert [r.prefix for r in routes] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert routes[0].peer_asn == 64511
    assert routes[0].origin_asn == 64496
    assert routes[1].origin_asn == 64502
    print("analyzer MRT offline interop: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
