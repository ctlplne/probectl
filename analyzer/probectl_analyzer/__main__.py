"""CLI entry point: ``python -m probectl_analyzer --config cfg.json --mrt dump.mrt``.

Emits ``probectl.bgp.events`` as JSON Lines on stdout (or ``--out``), which the Go
``internal/bgp`` bridge republishes onto the bus.
"""

from __future__ import annotations

import argparse
import sys

from .config import AnalyzerConfig
from .emit import JsonlSink
from .log import configure, get_logger
from .pipeline import Analyzer, load_vrp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probectl-analyzer", description="probectl BGP analyzer")
    parser.add_argument("--config", required=True, help="path to the analyzer JSON config")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--mrt", help="process an MRT dump (RouteViews / RIS bulk)")
    source.add_argument("--replay", help="replay a recorded RIS Live JSONL capture")
    source.add_argument(
        "--ris-live", action="store_true", help="stream from the RIS Live websocket"
    )
    parser.add_argument("--out", help="write events here (default: stdout)")
    args = parser.parse_args(argv)

    config = AnalyzerConfig.from_file(args.config)
    configure(config.log_level)
    log = get_logger()
    vrp = load_vrp(config)
    if vrp is not None:
        log.info("loaded RPKI VRP set", count=len(vrp))

    out = open(args.out, "w", encoding="utf-8") if args.out else sys.stdout
    try:
        analyzer = Analyzer(config, JsonlSink(out), vrp)
        if args.mrt:
            with open(args.mrt, "rb") as fp:
                events = analyzer.process_mrt(fp)
            log.info("processed MRT dump", file=args.mrt, events=events)
        elif args.replay:
            with open(args.replay, encoding="utf-8") as fp:
                events = analyzer.process_ris_replay(fp)
            log.info("processed RIS Live replay", file=args.replay, events=events)
        else:
            from .rislive import RISLiveClient

            client = RISLiveClient(
                host=config.collector or None,
                prefixes=[mp.prefix for mp in config.monitored_prefixes],
            )
            log.info("streaming RIS Live (Ctrl-C to stop)")
            analyzer.process_routes(client.routes())
    finally:
        if args.out:
            out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
