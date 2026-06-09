# analyzer/ — probectl BGP analyzer (Python)

The BGP analyzer is the one probectl component written in Python (the language has
the richest BGP/MRT libraries). It ingests **public** collector data — **RouteViews**
(bulk MRT over HTTP) and **RIPE RIS** (MRT + the **RIS Live** websocket) — does
per-prefix AS-path monitoring with origin-change / hijack / leak detection and
**RPKI** (RFC 6811) validation, and emits `probectl.bgp.events` as JSON Lines. The Go
side (`internal/bgp`) bridges those onto the bus as the canonical
`probectl.bgp.v1.BGPEvent` protobuf, tenant-keyed.

## Modules

| Module | Responsibility |
| ------ | -------------- |
| `mrt.py` | streaming RFC 6396 parser (TABLE_DUMP_V2 RIB + BGP4MP UPDATE) — yields routes one at a time |
| `rislive.py` | RIS Live JSON parsing (replayable core) + a reconnecting websocket client |
| `rpki.py` | RFC 6811 route-origin validation against a VRP set |
| `monitor.py` | per-prefix baseline + origin-change / possible-hijack / possible-leak detection |
| `events.py` | the `BGPEvent` schema (its JSON form is the contract with the Go bridge) |
| `config.py` | monitored prefixes, expected origins, no-transit ASNs, RPKI source, tenant (loaded from JSON) |
| `emit.py` | JSON-Lines event sink (a Kafka sink is a future addition) |
| `log.py` | `structlog` setup (JSON log lines on stderr — no `print`) |
| `pipeline.py` / `__main__.py` | wiring + CLI |

## Usage

```sh
pip install -e '.[dev]'                         # from analyzer/
# (optional) live RIS Live needs the websocket extra:
pip install websockets

# process a RouteViews / RIS MRT dump
python -m probectl_analyzer --config config.json --mrt rib.20260101.0000.bz2.mrt

# replay a recorded RIS Live capture (JSON Lines)
python -m probectl_analyzer --config config.json --replay ris-capture.jsonl

# stream live from RIS Live (writes JSONL to stdout)
python -m probectl_analyzer --config config.json --ris-live --out /var/lib/probectl/bgp-events.jsonl
```

Events are written as JSON Lines to stdout (or `--out FILE`). The Go side
(`internal/bgp`) is a **bridge package embedded in the control plane**, not a
standalone CLI: it reads this JSONL stream, validates each event's tenant, and
republishes onto the bus as the `probectl.bgp.v1.BGPEvent` protobuf. Wire the
analyzer's output to that reader (e.g. a file/pipe the control plane consumes).

### Config (`config.json`)

```json
{
  "tenant_id": "acme",
  "collector": "rrc00",
  "rpki_vrp_file": "vrps.json",
  "monitored_prefixes": [
    {"prefix": "192.0.2.0/24", "expected_origins": [64496], "no_transit": [64666]}
  ]
}
```

`tenant_id` is required — every emitted event carries it, and the bridge rejects
any event without one. `rpki_vrp_file` (or `rpki_vrp_url`) points at a
`rpki-client` / Routinator VRP JSON export; omit it and RPKI status degrades to
`unknown`.

## Conventions

- `structlog` for structured logging — no `print` in production code.
- Stream-process MRT dumps; never load full RIB tables into memory.
- Treat all fetched collector data as **untrusted**; fetch over TLS with
  certificate validation; a down/rate-limited source degrades gracefully
  (CLAUDE.md §7 guardrails 10, 12).
- Detections are **signals** (confidence + severity, tunable), never actions
  (guardrail 9).
- RouteViews/RIS are open data; their AUP/provenance is tracked for MSP/commercial
  resale (not for private development or single-tenant OSS use).

## Development

```sh
make lint-python          # ruff check + black --check   (from repo root)
make test-python          # pytest                        (from repo root)
```
