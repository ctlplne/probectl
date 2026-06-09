# ADR: rebuild-on-restart for the in-process derived stores

- **Status:** Accepted — 2026-06-07
- **Context:** a review noted that topology, threat detections, and alert
  firing state live in process memory and are lost when the control plane
  restarts. This ADR decides whether that is a bug to fix or a property to
  accept.

## The plain version

Some of probectl's state lives only in RAM inside the control plane. When the
process restarts, that RAM is gone. The question is: do we add a database to
persist it, or is losing it actually fine?

The answer for three of these stores is: **it's fine, because they are
*derived* — they are a cache of something durable, not the original copy.**
Think of them like a search index over your email: if the index is wiped, you
don't lose any email; the index just rebuilds itself by re-reading the mailbox.
Same here. So we **formally adopt rebuild-on-restart** for them rather than
adding persistence — and we prove the cold-start behavior with tests. One
genuinely non-derivable piece of state (alert silences/acks) is the exception
and is called out as a tracked gap rather than silently dropped.

## Decision

Three in-process stores are **derived views of a durable source**, not systems
of record:

| Store | What it holds | Durable source it re-derives from | Restart behavior |
|---|---|---|---|
| `internal/topology` (`MemoryStore` / `IndexedStore`) | the tenant-scoped temporal graph | the bus stream (`probectl.ebpf.flows` and friends) plus the path/flow stores it observes; the topology consumer re-subscribes at boot | **rebuilds** as new observations arrive; a cold start is an empty graph that refills within the stream/retention window |
| `internal/threat` (`DetectionStore`) | recent NDR/posture detections per tenant, bounded | the detection stream; the **durable trail is the incident record + SIEM export**, which is already persisted | **rebuilds** from the stream; the forensic copy already left via incidents/SIEM, so nothing forensic is lost |
| `internal/alert` (`Engine` firing state) | per-series firing/pending state | re-derived on the **next evaluation** against the metric source | firing state **re-derives** automatically (see the exception below) |

## Why rebuild rather than persist

These are **caches of a stream**, not the system of record. The authoritative
data already lives durably: flows and paths in ClickHouse, metric series in the
TSDB, the detections' forensic copy in incidents plus the SIEM export, and the
audit trail in its tamper-evident chain.

Persisting a *second* copy of a derived view would buy us nothing and cost
three things:

1. **Write-path cost** — every observation would have to be written twice.
2. **A schema to migrate** — more migrations, more surface.
3. **A consistency problem** — the persisted snapshot and the live stream can
   disagree, and now you have to reconcile them.

…all for state that is correct again within one evaluation or observation
cycle. Rebuild-on-restart is the simpler, correct choice — and it is now a
**decided, tested** property instead of an implicit one.

Cross-tenant isolation is unaffected. Each store is keyed by tenant, and a cold
start cannot surface another tenant's data: it surfaces *nothing* until it has
re-derived from that tenant's own inputs.

## The exception: alert silences and acknowledgements

Silences and acks are **operator inputs**, not derivable from any stream.
Re-deriving firing state can reconstruct *what is firing*, but it cannot
reconstruct "operator X silenced this alert until 3pm" — that fact existed only
because a human typed it. Today silences/acks are in-process and **lost on
restart**: a silenced-but-still-firing alert simply reappears un-silenced.

That failure mode is deliberately the safe direction — **louder, not
quieter.** A restart can never *hide* a firing alert; the worst case is that a
human has to re-apply a silence. This is the one real durability gap. It is
documented in code (`internal/alert/active.go`) and tracked as a follow-up:
silences/acks should ride a small Postgres-backed table the same way alert
*rules* already do. Until then, operators re-apply silences after a
control-plane restart.

## Consequences

- A control-plane restart shows a briefly empty topology/detection view and
  reappearing (un-silenced) firing alerts — expected and documented.
- No new migration, write path, or snapshot-consistency surface for derived
  state.
- The cold-start contract is enforced by tests in `internal/topology` and
  `internal/alert`: a fresh store is empty and correct, and re-derives from its
  inputs.

## Tests proving cold start

- `internal/topology`: a new `MemoryStore` returns an empty snapshot for any
  tenant (no stale data, no panic) and rebuilds the graph as observations
  replay.
- `internal/alert`: a new `Engine` has no active alerts and no silences/acks at
  construction, and re-derives firing state from the metric source on the first
  evaluation after a restart (modeled as a fresh engine).
