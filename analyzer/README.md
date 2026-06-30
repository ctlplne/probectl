# analyzer/ — probectl BGP analyzer (Python)

The BGP analyzer is the one probectl component written in Python (the language has
the richest BGP/MRT libraries). It ingests **public** collector data — **RouteViews**
(bulk **MRT** over HTTP; MRT, RFC 6396, is the standard binary archive format for
BGP table snapshots and update streams) and **RIPE RIS** (MRT + the **RIS Live**
websocket, RIPE's real-time feed of BGP messages) — does per-prefix AS-path
monitoring with origin-change / hijack / leak detection and **RPKI** (RFC 6811)
validation (checking each announcement against cryptographically published
statements of which AS may originate a prefix), and emits `probectl.bgp.events`
as JSON Lines (one JSON object per line — streamable, no enclosing array). The Go
side (`internal/bgp`) bridges those onto the bus as the canonical
`probectl.bgp.v1.BGPEvent` protobuf, tenant-keyed. Direct router BMP ingest lives
in Go (`probectl-bmp-listener`) because it is a served mTLS socket, not a public
collector fetch.

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
# (optional) live RIS Live streaming needs the websockets package
# (imported lazily — MRT/replay processing works without it):
pip install websockets

# process a RouteViews / RIS MRT dump
python -m probectl_analyzer --config config.json --mrt rib.20260101.0000.bz2.mrt

# replay a recorded RIS Live capture (JSON Lines)
python -m probectl_analyzer --config config.json --replay ris-capture.jsonl

# stream live from RIS Live, writing JSONL to a file instead of stdout
python -m probectl_analyzer --config config.json --ris-live --out /var/lib/probectl/bgp-events.jsonl
```

Events are written as JSON Lines to stdout (or `--out FILE`). The Go side
(`internal/bgp`) is a **bridge package embedded in the control plane**, not a
standalone CLI: it reads this JSONL stream, validates each event's tenant, and
republishes onto the bus as the `probectl.bgp.v1.BGPEvent` protobuf. Wire the
analyzer's output to that reader (e.g. a file/pipe the control plane consumes).

For router-native BMP (BGP Monitoring Protocol), use `probectl-bmp-listener`
instead. It accepts mTLS sessions, derives the tenant from the peer certificate,
and publishes into the same `probectl.bgp.events` topic.

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
any event without one (fail closed: an unattributable event is dropped, never
guessed). `rpki_vrp_file` (or `rpki_vrp_url`) points at a `rpki-client` /
Routinator VRP JSON export (a **VRP**, Validated ROA Payload, is one
prefix→origin-AS authorization an RPKI validator has verified); omit it and
RPKI status degrades to `unknown` rather than blocking analysis.

## Conventions

- `structlog` for structured logging — no `print` in production code.
- Stream-process MRT dumps; never load full RIB tables into memory.
- Treat all fetched collector data as **untrusted**; fetch over TLS with
  certificate validation; a down/rate-limited source degrades gracefully and
  never breaks core function.
- Detections are **signals** (confidence + severity, tunable), never actions —
  probectl is not an IPS.
- RouteViews/RIS are open data; their AUP/provenance is tracked for MSP/commercial
  resale (not for private development or single-tenant OSS use) — see
  [`docs/opendata-aup.md`](../docs/opendata-aup.md).

These are project-wide rules, not analyzer quirks — the full list is
[CONTRIBUTING.md → Non-negotiables](../CONTRIBUTING.md#non-negotiables).

## Development

```sh
make lint-python          # ruff check + black --check        (from repo root)
make test-python          # pytest, with an 85% coverage floor (from repo root)
```

The tests run entirely offline against **recorded fixtures** — a fixture is a
checked-in, known-good input a test replays, here hand-built MRT byte streams
(`tests/mrt_fixtures.py`) and in-repo RIS Live message fixtures — so no test
ever reaches a live collector, and a collector outage can never redden CI. CI
installs the analyzer from the hash-locked `requirements-dev.lock` (every
dependency pinned by content hash, so a tampered upstream package cannot
install) and fails if that lock drifts from `pyproject.toml`.
