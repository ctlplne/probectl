# ADR: rebuild-on-restart for the in-process derived stores

- **Status:** Accepted — 2026-06-07. **Addendum:** the one durability gap this
  ADR tracked (alert silences/acks, the exception below) has since been closed
  — they now persist in a tenant-scoped Postgres table and are restored on
  boot. The rebuild-on-restart decision for the three *derived* stores is
  unchanged.
- **Context:** a review noted that topology, threat detections, and alert
  firing state live in process memory and are lost when the control plane
  restarts. This ADR — an architecture decision record, a dated note capturing
  a decision and its why, kept even after the code moves on — decides whether
  that is a bug to fix or a property to accept.

## The plain version

A **volatile** store lives in process RAM and vanishes when the process exits;
a **durable** one is written to disk or a database and survives. Some of
probectl's state is volatile: it lives only in RAM inside the control plane,
and when the process restarts, that RAM is gone. The question is: do we add a
database to persist it, or is losing it actually fine?

The answer for three of these stores is: **it's fine, because they are
*derived* — they are a cache of something durable, not the original copy.**
Think of them like a search index over your email: if the index is wiped, you
don't lose any email; the index just rebuilds itself by re-reading the mailbox.
Same here. So we **formally adopt rebuild-on-restart** for them rather than
adding persistence — and we prove the **cold-start** behavior (what each store
looks like in the first moments after a restart, before anything has been
re-derived) with tests. One genuinely non-derivable piece of state (alert
silences/acks) is the exception: it was called out as a tracked gap rather
than silently dropped, and has since been fixed with a small persisted table
(see the exception section).

## Decision

Three in-process stores are **derived views of a durable source**, not systems
of record (the system of record is the authoritative copy you would restore
from — these are never that):

| Store | What it holds | Durable source it re-derives from | Restart behavior |
|---|---|---|---|
| `internal/topology` (`MemoryStore` / `IndexedStore`) | the tenant-scoped temporal graph | the bus stream (`probectl.ebpf.flows` and friends) plus the path/flow stores it observes; the topology consumer re-subscribes at boot | **rebuilds** as new observations arrive; a cold start is an empty graph that refills within the stream/retention window |
| `internal/threat` (`DetectionStore`) | recent NDR/posture detections per tenant, bounded | the detection stream; the **durable trail is the incident record + SIEM export**, which is already persisted | **rebuilds** from the stream; the forensic copy already left via incidents/SIEM, so nothing forensic is lost |
| `internal/alert` (`Engine` firing state) | per-series firing/pending state | re-derived on the **next evaluation** against the metric source | firing state **re-derives** automatically (see the exception below) |

## Why rebuild rather than persist

These are **caches of a stream**, not the system of record. The authoritative
data already lives durably: flows and paths in ClickHouse, metric series in the
TSDB (the time-series database), the detections' forensic copy in incidents
plus the SIEM export (security information and event management — the
organization's central security-event collector), and the audit trail in its
tamper-evident chain.

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

A **silence** mutes an alert's notifications until a chosen time; an **ack**
(acknowledgement) marks who has taken ownership of it. Both are **operator
inputs**, not derivable from any stream. Re-deriving firing state can
reconstruct *what is firing*, but it cannot reconstruct "operator X silenced
this alert until 3pm" — that fact existed only because a human typed it. When
this ADR was accepted, silences/acks were in-process and **lost on restart** —
deliberately failing in the safe direction, **louder, not quieter**: a restart
could never *hide* a firing alert; the worst case was a human re-applying a
silence.

That tracked follow-up has since landed. Silences and acks now ride a small
tenant-scoped Postgres table (`alert_ops`, migration `0043_alert_ops.sql`,
RLS-confined — row-level security, where the database itself filters every
query to the calling tenant's rows) the same way alert *rules* already do:
written when the operator acts, reloaded at boot, re-applied when their series
fires again, and deleted when the episode resolves — so restart-restored state
never outlives the episode semantics the in-memory engine always had. The
fail-louder ordering is preserved: if the reload itself fails, alerting
continues without the saved silences (logged loudly) rather than blocking on
the table.

## Consequences

- A control-plane restart shows a briefly empty topology/detection view while
  the streams re-fill — expected and documented. Firing alerts re-derive on
  the first evaluation, with persisted silences/acks re-applied as their
  series fire.
- No new migration, write path, or snapshot-consistency surface for *derived*
  state. (The silences/acks fix is exactly the carve-out the exception
  predicted: one small table for non-derivable operator input — not a second
  copy of any stream.)
- The cold-start contract is enforced by tests in `internal/topology` and
  `internal/alert`: a fresh store is empty and correct, and re-derives from its
  inputs.

## Tests proving cold start

- `internal/topology`: a new `MemoryStore` returns an empty snapshot for any
  tenant (no stale data, no panic) and rebuilds the graph as observations
  replay.
- `internal/alert`: a new `Engine` has no active alerts and no silences/acks at
  construction, and re-derives firing state from the metric source on the first
  evaluation after a restart (modeled as a fresh engine). The engine itself
  stays memory-only by design — durability is the wiring around it, which
  persists operator actions and restores them at boot.
