# Data Retention Matrix

**What this is.** One privacy map for the data probectl keeps: what kind of data
it is, why it exists, where it lives, and what clock deletes it. ELI5: every data
set is a labeled box. The label says what is inside, why we are allowed to keep
it, which shelf it sits on, and which timer removes it.

This page is a governance/control map, not a new retention engine. Today,
retention is still enforced by the owning stores and lifecycle paths:
ClickHouse TTLs plus ClickHouse hourly rollups, the in-memory TSDB window, audit
pruning after durable export, AI-answer pruning on write, and tenant/subject
erasure. `flow_retention_days is the only tenant-scoped age-retention override
today`; other age clocks are deployment-level settings unless the tenant is
siloed onto separately configured stores.

## Enforcement Model

- **Tenant first, then purpose.** Every retained row, object key, metric, and
  export cursor is tenant-scoped before RBAC or governance policy is considered.
  If the tenant cannot be proven, the read/delete path returns nothing.
- **Age retention is store-owned.** High-volume ClickHouse stores use delete
  TTLs for raw rows and hourly rollup tables for lower-resolution history; the
  in-memory TSDB uses an arrival-time window; audit logs prune only after
  WORM/SIEM export proves the evidence survived elsewhere.
- **Lifecycle deletion is wider than age retention.** Tenant erase and subject
  erase are the privacy "big brooms": they remove or project data across live
  stores even when a store has no age TTL.
- **Copies keep their own clock.** Backups, WORM exports, and customer SIEM
  destinations are not live stores. probectl records the configured backup
  window and export cursor, but the destination system owns its own retention.
- **No object-store age TTL is enforced by FSStore.** The filesystem object
  store keeps objects until tenant erase/subject erase, explicit prefix delete,
  or the operator's bucket/filesystem lifecycle policy removes them.

## Data-Class And Purpose Matrix

| Data set | Default class | Purpose | Primary home | Retention and deletion clock |
|---|---|---|---|---|
| Synthetic/canary probe results, including **DNS answers** | `pii` for IPs/targets; `internal` for labels; result attributes may carry tenant data | Network and SLO troubleshooting: "did this tenant's path resolve and respond?" | TSDB series, result views, and bus payloads under `tenant_id` | Lightweight mode uses `PROBECTL_TSDB_MEMORY_RETENTION` (`0` means the built-in 1h window). Remote Prometheus/VictoriaMetrics retention is configured in that TSDB. Tenant erase deletes in-memory series or calls the Prometheus admin delete-series path when enabled; otherwise the attestation records the manual step. DNS answers live inside the result attributes, so they follow the probe-result clock. |
| Flow telemetry | `pii` for source/destination IPs; `confidential` for ports/protocols/ASN enrichment | Traffic accounting, segmentation evidence, incident context, and cost attribution | ClickHouse `probectl_flows` plus hourly `probectl_flow_rollups_hour`, or in-memory flow store | `PROBECTL_FLOW_RETENTION_DAYS` defaults to 90 days and applies a ClickHouse delete TTL to raw rows; `0` is an explicit keep-forever opt-out. Hourly rollups are tenant-partitioned, backfillable, and remain queryable after raw rows age out until tenant/subject erase removes matching rollup rows. Per-tenant `flow_retention_days` can tighten the raw-row clock. |
| eBPF host/L7 flow telemetry | `pii` for peer IPs and process/user-adjacent labels; `confidential` for service edges | Host/service dependency mapping, L7 observability, and NDR-lite signals | ClickHouse eBPF tables or in-memory eBPF store | `PROBECTL_EBPF_RETENTION_DAYS` defaults to 30 days and applies eBPF ClickHouse TTLs; `0` disables that age TTL. Tenant erase removes the tenant's live eBPF rows. |
| Path/traceroute evidence and **Topology labels** | `pii` for hop IPs; `internal` or `confidential` for hostnames, interface labels, sites, and topology annotations | Change-aware topology, path RCA, and blast-radius reasoning | ClickHouse path tables plus hourly path hop/link rollups and `internal/topology` memory/index stores | `PROBECTL_PATH_RETENTION_DAYS` defaults to 90 days for raw path/traceroute ClickHouse TTLs. Hourly hop/link rollups keep lower-resolution tenant-scoped history while raw path rows age out. The topology memory/index store has no independent time TTL; it rebuilds from fresh observations and is cleared by tenant deletion (`DeleteTenant`) or process restart. |
| OTLP traces and logs | `pii` or `restricted` when attributes/bodies contain user IDs, IPs, emails, tokens, or request data | Application/host correlation with network incidents | ClickHouse OTLP store or memory store | `PROBECTL_OTEL_RETENTION_DAYS` defaults to 30 days for ClickHouse trace/log TTLs; `0` disables that TTL. Attribute/body caps and redaction reduce blast radius, but tenant/subject erase is the privacy deletion path for matching OTLP data. |
| Device telemetry, endpoint/DEM metrics, and SNMP/gNMI attributes | `pii` for management IPs and endpoint-user identifiers; `confidential` for inventory/config posture | Device health, endpoint experience, and operational inventory correlation | TSDB, device/endpoint stores, and tenant-scoped API views | Metric samples follow the TSDB retention clock (`PROBECTL_TSDB_MEMORY_RETENTION` in memory mode or the remote TSDB's policy). Durable inventory/config rows are lifecycle-managed and erased with the tenant or data subject; they do not currently have a separate age TTL. |
| **User directory attributes**, RBAC, SCIM, sessions, and tenant membership | `pii` for names/emails; `restricted` for credentials/tokens; `confidential` for roles and groups | Authentication, authorization, provisioning, and audit attribution | Postgres tenant tables with RLS and envelope-sealed secrets where applicable | Kept while the identity/tenant is active. User deprovision, subject erase, and tenant erase are the deletion paths. Tokens/secrets are stored as hashes or sealed values; no age TTL exists for directory rows unless the owning subsystem adds one. |
| **Audit entries**, provider audit, break-glass records, and WORM segments | `confidential` to `restricted` because they prove who touched what | Non-repudiation, compliance evidence, incident response, and break-glass accountability | Postgres audit chains plus optional signed WORM object segments | `PROBECTL_AUDIT_RETENTION` defaults to `0` (keep forever). A positive window can prune only events older than the window and already durably WORM/SIEM-exported; fail closed means un-exported evidence is never deleted and the in-DB hash chain is not gapped. Subject erase projects matching audit reads/exports with an erased token while preserving chain integrity. |
| **AI prompts and answers**, feedback, citations, and model/config hashes | `pii` or `restricted` when evidence contains tenant telemetry, operator text, or secrets | RCA reproducibility, dispute resolution, and answer quality feedback | Optional privacy-minimized Postgres answer artifacts and feedback rows; remote model side only when explicitly enabled | `PROBECTL_AI_PERSIST_ANSWERS=false` means answers are not persisted by default. When enabled, the stored answer and `ai.ask` audit question are tokenized before they enter Postgres; `PROBECTL_AI_ANSWER_RETENTION` defaults to `2160h` (90 days) and is pruned opportunistically on write. Tenant/subject erase removes matching persisted answers. Remote model retention is outside probectl and is allowed only through the remote-AI egress gates. |
| **Object artifacts**: support bundles, lifecycle exports, test bundles, browser artifacts, backup/WORM files | Usually `confidential`; may be `restricted` when logs, configs, screenshots, or audit evidence are included | Portability, support, test distribution, backup/restore, and immutable audit export | Object store: filesystem, S3, or MinIO under tenant prefixes/buckets | No object-store age TTL is enforced by FSStore. Tenant erase deletes the tenant prefix through the objectstore `DeletePrefix` path. Backup files follow `PROBECTL_BACKUP_RETENTION_DAYS` and `PROBECTL_BACKUP_RETENTION_NOTE` in the deletion attestation, plus the operator's bucket/object-lock lifecycle policy. |
| Open-data and threat-intel shared feeds | `public` or source-license-governed shared data | Enrichment: ASN/RPKI/peering, outage context, CT/threat-intel matches | Shared feed caches and threat/opendata stores | These are ingested once, read-only, and scoped when joined to tenant data. They are not tenant telemetry. Retention/cache TTL is source-specific and must honor source AUP/provenance; source outages degrade gracefully. |
| **SIEM-exported copies** and SIEM cursors | Exported events are `confidential`; redaction removes known secrets/PII keys before forwarding | Customer SOC correlation and long-term security evidence | Customer SIEM plus probectl's per-tenant delivery cursor | SIEM retention is owned by the destination SIEM. probectl keeps only the cursor needed to resume delivery without dropping events; audit retention may prune local events only after durable WORM/SIEM export. |
| Backups and snapshots | Same class as the source data, usually `restricted` | Disaster recovery and regulated rollback | Operator backup system, sealed backups, database/object-store snapshots | Live-store erasure does not instantly purge historical backups. `PROBECTL_BACKUP_RETENTION_DAYS` records a concrete backup-erasure deadline in the tenant-erasure attestation; `PROBECTL_BACKUP_RETENTION_NOTE` records the operator's human-readable backup policy. |

## Config Clocks

| Clock | Default | Scope | What it controls |
|---|---|---|---|
| `PROBECTL_TSDB_MEMORY_RETENTION` | `0` = built-in 1h | Deployment | In-memory TSDB sample window. |
| `PROBECTL_FLOW_RETENTION_DAYS` | `90` | Deployment, with tenant override via `flow_retention_days` | ClickHouse raw-flow delete TTL; hourly flow rollups remain until lifecycle deletion. |
| `PROBECTL_EBPF_RETENTION_DAYS` | `30` | Deployment | ClickHouse eBPF delete TTL. |
| `PROBECTL_PATH_RETENTION_DAYS` | `90` | Deployment | ClickHouse raw path/traceroute delete TTL; hourly path rollups remain until lifecycle deletion. |
| `PROBECTL_OTEL_RETENTION_DAYS` | `30` | Deployment | ClickHouse OTLP trace/log delete TTL. |
| `PROBECTL_AUDIT_RETENTION` | `0` = keep forever | Deployment | Audit prune eligibility after durable WORM/SIEM export. |
| `PROBECTL_AI_PERSIST_ANSWERS` | `false` | Deployment | Whether AI answers are stored at all. |
| `PROBECTL_AI_ANSWER_RETENTION` | `2160h` | Deployment | Age window for persisted AI answers when persistence is enabled. |
| `PROBECTL_BACKUP_RETENTION_DAYS` | `0` = note-only | Deployment/operator policy | Backup-erasure deadline recorded in deletion attestations. |
| `PROBECTL_BACKUP_RETENTION_NOTE` | Generic fallback | Deployment/operator policy | Human-readable backup retention statement in deletion attestations. |

## Practical Reading

- If an auditor asks "how long do flow rows live?", start at the flow row and
  check `PROBECTL_FLOW_RETENTION_DAYS`, then check whether the tenant has a
  tighter `flow_retention_days` override.
- If they ask about a person, use subject export/erase. Age TTLs are coarse
  timers; subject lifecycle is the tenant-scoped privacy control.
- If they ask about backups or SIEM, give the probectl attestation/cursor plus
  the operator's SIEM or backup policy. probectl cannot truthfully promise the
  destination deleted its copy.
