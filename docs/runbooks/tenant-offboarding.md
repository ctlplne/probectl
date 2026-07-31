# Runbook: tenant offboarding (export → erase → attest)

## What this is

The clean way to remove a tenant: hand them their data, irreversibly delete it
from every store, and produce a signed attestation that it's gone. An
**attestation** is a recorded statement of fact you can hand to an auditor —
here, per-store deletion counts and verified-zero checks, hash-anchored to a
tamper-evident log so it can't be edited after the fact. **Verifiable** is the
load-bearing word throughout: the engine never just issues deletes and hopes —
it re-reads every store afterward and records the zero. **Export and
verifiable deletion are core** — a compliance right available in every edition,
not a paid add-on. The provider-console trigger is just the MSP convenience layer
over the same engine.

## 0. Before you start

- Confirm the request's authority (a tenant admin or the contract owner).
- Know your **backup TTL** (time-to-live — the age at which a snapshot is
  automatically deleted). Deletion of the *live* stores is attested
  immediately, but snapshots expire on *your* schedule. Set
  `PROBECTL_BACKUP_RETENTION_NOTE` (e.g. "nightly snapshots, 14-day TTL,
  region X") so every attestation states it verbatim. An attestation that says
  nothing about backups is incomplete in spirit — be explicit.

## 1. Export (portability)

Tenant self-service: **Admin → Data lifecycle → Export my data**, or
`GET /v1/lifecycle/export` (permission `lifecycle.export`). The bundle is a
`tar.gz` containing:

- `manifest.json` — row counts, object inventory, and format notes
  (`format_version: 1`);
- `postgres/<table>.jsonl` — ordinary tenant-owned rows, one JSON object per
  line;
- `flows.jsonl` — every flow record, streamed from the flow store.
- `endpoint_events.jsonl` — every raw endpoint/DEM event, streamed through the
  tenant-scoped event-store boundary.

Ordinary portability never reads, unseals, or exports the provider-only
encrypted incident-response attribution sidecar. That evidence is accessible
only through the audited `ir-investigator` separation-of-duty path. Every
manifest carries the same fixed policy note, whether or not evidence exists, so
the bundle exposes neither sidecar contents nor a presence/absence signal.

Time-series metrics are **not** in the bundle: export them via the
Prometheus-compatible API (federation / PromQL) — the manifest says so. Hand the
bundle to the customer **before** you erase anything.

## 1a. Subject export / erasure (data-subject request)

A subject request is the smaller privacy workflow: remove or return the rows
that mention one person or identifier **inside one tenant**, without deleting
the whole tenant. Think "empty Alice's folder in tenant A," not "search every
tenant for Alice." The tenant id is still the outer wall: probectl chooses the
caller's tenant first, then applies the subject filter inside that tenant.

Export uses `POST /v1/lifecycle/subjects/export` (permission
`lifecycle.export`):

```json
{"subject":"alice@example.com","redact":true}
```

The response is `probectl-subject-export.tar.gz`. It contains `manifest.json`
with only a tenant-scoped subject hash, plus matching JSONL files such as
`postgres/users.jsonl`, `flows.jsonl`, `otel_spans.jsonl`, and
`otel_logs.jsonl`, `tsdb_metrics.jsonl`, `topology_subject.jsonl`,
`ebpf_edges.jsonl`, and `endpoint_subject.jsonl` when those planes contain
matching rows. RUM host/path labels are covered by `tsdb_metrics`; device labels
are counted from topology device nodes. The raw subject is in the exported data
because this is the tenant's portability bundle; it is not stored in the
manifest or provider audit receipt.

CLI equivalent:

```bash
probectl lifecycle subject-export --subject alice@example.com --redact > subject-export.tar.gz
```

Erasure uses `POST /v1/lifecycle/subjects/erase` (permission
`lifecycle.erase`):

```json
{"subject":"alice@example.com","confirm":"alice@example.com","reason":"dsar"}
```

The exact confirmation is deliberate friction for an irreversible action. The
engine removes matching identity rows, persisted AI answers, flow rows, OTLP
trace/log rows, in-memory TSDB metric labels, topology/device graph labels,
eBPF workload aggregates, and endpoint latest-view labels for the caller's
tenant only when those stores are wired. Audit rows are append-only, so the
engine records a `privacy.subject_erase` marker instead of rewriting history;
the same transaction records its tenant-scoped hash in
`audit_subject_erasures`. Future audit reads/exports project matching structured
actor/target/data values as `[erased-subject]` while the hash chain stays
verifiable. Classified Postgres deletions and every captured stable-alias
marker/projection share one tenant transaction, so a failed marker cannot leave
identity rows deleted without their privacy projection. Subject and full-tenant
bundles use the same projected audit serializer and retain the tenant,
sequence, timestamp, and chain fields. Exported marker events can later age out
without losing that projection; retention captures marker-only events from a
rolling older binary before it deletes them. Aggregate backends that cannot
locally delete a single subject are not hidden: the returned report lists each
plane's deleted and remaining counts, `not_capable`/age-out basis where needed,
and includes `report_sha256`.

CLI equivalent:

```bash
probectl lifecycle subject-erase --subject alice@example.com --confirm alice@example.com --reason dsar
```

## 2. Suspend, then offboard (provider console)

Suspend stops the tenant's users from logging in. Offboard then frees the
licensed tenant-band slot and blocks tenant access. Offboard is deliberately
non-destructive for every isolation model: it does not reclaim the silo, so the
encrypted incident-response sidecar and its signed chain remain available to
the verified erase plan.

## 3. Erase (irreversible, verifiable)

Provider console (admin): **tenant row → Erase**, or
`POST /provider/v1/tenants/{id}/erase` with body `{"confirm":"<tenant-slug>"}`.
Tenant-side, the equivalent is `POST /v1/lifecycle/erase` (permission
`lifecycle.erase`). The engine walks every store, deletes the tenant's data, and
verifies each store reads zero afterward. Note the Postgres deletes run under
the same row-level security (RLS) scope as live queries — the eraser is
*incapable* of reaching another tenant's rows, even buggy:

Before the first delete, the engine changes the tenant to `offboarding`, sets
the write-once `audit_write_fenced_at` marker, and records that transition while
holding the tenant-wide writer lock and the tenant's audit-stream lock.
PostgreSQL rejects clearing the marker or reopening a fenced tenant. Every
ordinary tenant-owned pooled or physical-silo table has an `ALWAYS`
INSERT/UPDATE trigger that takes the matching shared writer lock and re-reads
the durable registry row. An in-flight writer therefore finishes before the
fence and is then erased; a later or rolling-old writer waits for the committed
transition and is rejected. The append-only `audit_events` and
`audit_subject_erasures` tables keep their stronger stream-lock triggers and
are deleted and count-verified in one routed transaction under that lock.
The production flow-store decorator applies the same contract to every
ClickHouse or in-memory flow `Insert`: it takes shared leases in canonical
tenant order, re-reads every tenant's durable lifecycle row, and holds the
leases through the actual backend write. A mixed-tenant batch is rejected
before any row reaches the backend if one tenant is fenced. Transient database
or lease errors fail the whole flow insert and are safe to retry; once the
offboarding fence commits, retries for that tenant remain rejected.
Endpoint/DEM event `Insert` uses the same durable lease at its store boundary,
including the lightweight memory backend and every pooled or silo-routed
ClickHouse target.
The eBPF aggregate store applies that identical contract before any service
edge batch enters its memory or pooled/silo-routed ClickHouse backend.
Provider-global lifecycle evidence and tenant-key destruction remain on their
separate provider-maintenance paths, so retrying an incomplete erase can still
record its bounded receipt or complete crypto-shred without reopening ordinary
tenant writes.

Provider-row deletion, the `deleted` registry tombstone, and the successful
attestation append commit together only after every data store and key domain
has completed. If establishing and auditing the fence fails, both changes roll
back. After the fence commits, any later or finalization failure leaves the
tenant `offboarding`, fenced, and retryable; correct the reported cause and
rerun the idempotent erase.

| Store | Mechanism | Verification |
|---|---|---|
| Postgres (pooled or silo-routed) | per-table `DELETE` **under the tenant's own scope** (RLS + silo routing — it cannot touch another tenant), multi-pass to satisfy intra-tenant foreign-key ordering | per-table `count(*) == 0` in-scope |
| Provider rows about the tenant (usage, quotas, break-glass, retention, and compatibility-window rows) | provider-role-scoped deletes | per-table count == 0 |
| ClickHouse flows | pooled: synchronous lightweight delete (`SETTINGS mutations_sync=2`); siloed: `DROP DATABASE` | post-delete count == 0 |
| ClickHouse endpoint/DEM events | pooled: tenant-predicate mutation; siloed: `DROP DATABASE` | post-delete count == 0 (`endpoint_events` in the attestation) |
| Object store (`PROBECTL_OBJECTSTORE_DIR`, when configured) | `DeletePrefix` on `tenant/<id>/` and `silo/<id>/`; browser synthetic artifacts use the same tenant-prefixed namespace | post-delete list is empty |
| Tenant keys (BYOK editions) | **crypto-shred** — every key version's wrapped key is nulled and the chain marked `destroyed`, so any ciphertext (including in still-live backups) is permanently unreadable, and destroyed chains refuse re-keying | versions-destroyed count on the attestation; unlicensed deployments record "no per-tenant keyring installed" |
| Provider IR attribution key | before any store delete, verify signed sidecar/WORM coverage and commit a signed exact-artifact plan; after every ordinary store succeeds, remove only that tenant's local public/encrypted-private artifacts and commit a signed tombstone. The encrypted sidecar remains as unreadable proof | `ir_attribution_keys` is verified only after exact artifact absence; plan/completion/failure receipts survive deletion. Mount the owner-only private-key directory for erase; missing capability or incomplete coverage fails before deletion |
| Time-series (TSDB) | memory mode: in-place series delete. Prometheus mode: the engine calls the admin `delete_series` API itself and verifies. **If that admin API is disabled, this becomes a MANUAL STEP** — run `delete_series` for `{tenant_id="<id>"}` yourself (or let retention expire it); the attestation marks this store incomplete until you do | per mode |

After Offboard, the isolated container remains until this erase completes.
Physical container reclamation requires a separate tombstone-aware maintenance
procedure; never use a raw schema drop, because that would erase the retained
encrypted IR sidecar.

> The engine also erases the other tenant-scoped planes the same way (path,
> topology, endpoint/DEM event history, and externally-ingested OTLP traces/logs) — they appear in the
> attestation's store list too. The table above is the representative subset most
> often asked about.

**Crypto-shred**, in one image: the tenant's data sitting inside your still-live
backups is a locked safe you can no longer walk up to — but you hold the only
key. Destroy every copy of the key and every such safe, reachable or not,
becomes scrap metal. That is how the engine can honestly attest deletion of
data *inside backups it never touches*: ciphertext without a key is not data.

For IR attribution, overwrite/unlink covers only the exact local artifacts
mounted to probectl. Destroy operator backups, snapshots, escrow copies, or an
external KMS handle separately. A signed probectl tombstone permanently refuses
a restored local artifact, but it cannot claim physical zeroization of storage
outside the operator-controlled mount.

The tenant registry row is then **tombstoned** (`status=deleted`): the row
remains as a referent for the attestation, but it holds no telemetry.

## 4. The attestation

The engine returns — and the tamper-evident **provider audit chain** records,
along with the report's SHA-256 — a deletion report: per-store deleted counts,
verified-zero flags, your backup-TTL statement, and a `complete` flag. **If
`complete` is false, the notes name exactly what remains** (e.g. the Prometheus
manual step) — finish it and re-run erase (it is idempotent). Hand the
attestation JSON to the customer; the SHA-256 on the provider chain is their
proof it was not edited after the fact.

## 5. After

- **Backups:** the attested deletion covers the live stores. Your snapshots
  expire on the stated TTL — do not restore an erased tenant's backup except
  under legal hold.
- **Custom-domain TLS:** if the tenant had a custom domain, remove its ingress
  certificate and DNS.
- **Agents:** the agents' mTLS identities die with the registry rows;
  decommission the tenant's agent hosts.
