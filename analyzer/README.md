# analyzer/ — netctl BGP analyzer (Python)

The BGP analyzer is the one netctl component written in Python (the language has
the richest BGP/MRT libraries). It ingests public collector data — **RouteViews**
(bulk MRT over HTTP) and **RIPE RIS** (MRT + the **RIS Live** websocket) — does
per-prefix AS-path monitoring and origin-change/hijack/leak detection with
**RPKI** validation status, and emits `netctl.bgp.events`. The Go side bridges it
into the control plane via `internal/bgp`.

## Status (S0)

Scaffold only. The analyzer is implemented in **S14**. This package exists now so
its tooling (ruff, black, pytest) and the `lint-python` / `test-python` CI jobs
are wired from day one. Logging uses `structlog` (CLAUDE.md §6).

## Development

```sh
pip install -e '.[dev]'   # from analyzer/
make lint-python          # ruff check + black --check   (from repo root)
make test-python          # pytest                        (from repo root)
```

## Conventions

- `structlog` for structured logging — no `print` in production code.
- Stream-process MRT dumps; never load full RIB tables into memory (S14).
- Treat all fetched collector data as **untrusted**; fetch over TLS with
  certificate validation (CLAUDE.md §7 guardrails 10, 12).
