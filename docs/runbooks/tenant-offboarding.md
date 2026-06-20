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
- `postgres/<table>.jsonl` — every tenant-owned row, one JSON object per line;
- `flows.jsonl` — every flow record, streamed from the flow store.

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
`otel_logs.jsonl` when those planes contain matching rows. The raw subject is
in the exported data because this is the tenant's portability bundle; it is not
stored in the manifest or provider audit receipt.

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
engine removes matching identity rows, persisted AI answers, flow rows, and OTLP
trace/log rows for the caller's tenant only. Audit rows are append-only, so the
engine records a `privacy.subject_erase` marker instead of rewriting history;
future audit reads/exports project matching structured actor/target/data values
as `[erased-subject]` while the hash chain stays verifiable. The returned report
lists each plane's deleted and remaining counts and includes `report_sha256`.

CLI equivalent:

```bash
probectl lifecycle subject-erase --subject alice@example.com --confirm alice@example.com --reason dsar
```

## 2. Suspend, then offboard (provider console)

Suspend stops the tenant's users from logging in. Offboard frees the licensed
band slot (the tenant-count band your license permits) and, for a siloed or
hybrid tenant, tears down that tenant's
**containers** (its dedicated schema / ClickHouse database). For a pooled tenant,
the rows still physically exist at this point — that's what step 3 erases.

## 3. Erase (irreversible, verifiable)

Provider console (admin): **tenant row → Erase**, or
`POST /provider/v1/tenants/{id}/erase` with body `{"confirm":"<tenant-slug>"}`.
Tenant-side, the equivalent is `POST /v1/lifecycle/erase` (permission
`lifecycle.erase`). The engine walks every store, deletes the tenant's data, and
verifies each store reads zero afterward. Note the Postgres deletes run under
the same row-level security (RLS) scope as live queries — the eraser is
*incapable* of reaching another tenant's rows, even buggy:

| Store | Mechanism | Verification |
|---|---|---|
| Postgres (pooled or silo-routed) | per-table `DELETE` **under the tenant's own scope** (RLS + silo routing — it cannot touch another tenant), multi-pass to satisfy intra-tenant foreign-key ordering | per-table `count(*) == 0` in-scope |
| Provider rows about the tenant (usage, quotas, branding, break-glass, retention) | provider-role-scoped deletes | per-table count == 0 |
| ClickHouse flows | pooled: synchronous lightweight delete (`SETTINGS mutations_sync=2`); siloed: `DROP DATABASE` | post-delete count == 0 |
| Object store | `DeletePrefix` on `tenant/<id>/` and `silo/<id>/` | post-delete list is empty |
| Tenant keys (BYOK editions) | **crypto-shred** — every key version's wrapped key is nulled and the chain marked `destroyed`, so any ciphertext (including in still-live backups) is permanently unreadable, and destroyed chains refuse re-keying | versions-destroyed count on the attestation; unlicensed deployments record "no per-tenant keyring installed" |
| Time-series (TSDB) | memory mode: in-place series delete. Prometheus mode: the engine calls the admin `delete_series` API itself and verifies. **If that admin API is disabled, this becomes a MANUAL STEP** — run `delete_series` for `{tenant_id="<id>"}` yourself (or let retention expire it); the attestation marks this store incomplete until you do | per mode |

> The engine also erases the other tenant-scoped planes the same way (path,
> topology, and externally-ingested OTLP traces/logs) — they appear in the
> attestation's store list too. The table above is the representative subset most
> often asked about.

**Crypto-shred**, in one image: the tenant's data sitting inside your still-live
backups is a locked safe you can no longer walk up to — but you hold the only
key. Destroy every copy of the key and every such safe, reachable or not,
becomes scrap metal. That is how the engine can honestly attest deletion of
data *inside backups it never touches*: ciphertext without a key is not data.

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
