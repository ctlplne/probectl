# Dead-letter replay (runbook)

When a store outage outlives a consumer's bounded retry budget, the original
record is **dead-lettered** — published verbatim (tenant key + original payload)
to a `probectl.deadletter.*` topic — rather than dropped. Dead-lettering is
counted and logged; telemetry loss is never silent. This runbook covers
draining a dead-letter topic back into the normal ingest path once the
underlying store has recovered (ARCH-001).

## When to use this

- A `*_dead_lettered_total` metric (per consumer, surfaced at `/metrics`) is
  non-zero / climbing — alert on it.
- A store (TSDB / ClickHouse) was down or degraded long enough that the retry
  budget was exhausted, and you want to re-ingest the parked records after the
  store is healthy again.

## Dead-letter topics → source topics

| Dead-letter topic                     | Replays onto              |
| ------------------------------------- | ------------------------- |
| `probectl.deadletter.results`         | `probectl.network.results`|
| `probectl.deadletter.device`          | `probectl.device.metrics` |
| `probectl.deadletter.flow`            | `probectl.flow.events`    |
| `probectl.deadletter.otlp.metrics`    | `probectl.otlp.metrics`   |
| `probectl.deadletter.otlp.traces`     | `probectl.otlp.traces`    |
| `probectl.deadletter.otlp.logs`       | `probectl.otlp.logs`      |

`probectl.deadletter.bgp` is intentionally not listed: the BGP incident
consumer currently leaves failed source messages uncommitted instead of
publishing a bounded-retry DLQ. `replay-deadletter` rejects that topic until a
real BGP DLQ producer exists.

## Procedure

1. **Confirm the store is healthy** — replaying into a still-broken store just
   re-parks the records.
2. **Drain the topic:**

   ```sh
   probectl-control replay-deadletter --topic probectl.deadletter.results
   ```

   The replayer drains the dead-letter topic and re-publishes each record onto
   its source topic, where the normal ingest consumers pick it up again. The
   original tenant key and payload are preserved verbatim — a replayed record
   lands with its original tenant and series, never reattributed. It uses the
   same bus the control plane uses (`PROBECTL_BUS_*`).

   Flags:

   - `--max-rate N` — throttle to N records/sec (avoid a thundering herd on a
     just-recovered store).
   - `--max N` — stop after N records.
   - `--idle 5s` — stop after this long with no new record (the drain is
     one-shot: it terminates when the topic is empty).

3. **Verify** — the command prints `replayed <n> record(s) ...`; confirm the
   target store's row/series counts increased and the `*_dead_lettered_total`
   metric is no longer climbing.

## Idempotency

Replay is at-least-once: re-ingested records pass back through the dedup layer
(per-result UUID / ReplacingMergeTree), so a record that was partially applied
before the outage is **not** double-counted. Replaying the same topic twice is
safe.

## Notes

- The replay runs tenant-scoped end to end (the key is the tenant), like every
  other ingest path — no cross-tenant mixing.
- A failed re-publish or broker flush leaves the record on the dead-letter topic
  (uncommitted), so a transient bus error during replay never loses a record.
