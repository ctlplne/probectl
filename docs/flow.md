# Flow analytics — NetFlow / IPFIX / sFlow / cloud flow logs

## What this is

Every router and switch can tell you, after the fact, *who talked to whom*: it
summarizes the packets it forwarded into **flow records** (a 5-tuple — source IP,
destination IP, source port, destination port, protocol — plus byte/packet
counts) and ships them off the box. NetFlow, IPFIX, and sFlow are the three
common wire formats for that export: **NetFlow** is Cisco's original (v5 with a
fixed layout, v9 template-based), **IPFIX** is the IETF standard that grew out
of v9, and **sFlow** ships sampled raw packet headers instead of summaries. For
cloud-first estates, probectl also imports already-exported **AWS VPC Flow
Logs**, **Azure NSG Flow Logs**, and **GCP VPC Flow Logs** from local files or
object-export pipelines; it does not call cloud APIs by default.

If a synthetic probe is placing a test call yourself, a flow record is a line
on the itemized phone bill: it can't tell you how the call *sounded*, but it
tells you — for every call, after the fact — who talked to whom, when, and for
how many bytes. probectl's **flow plane** is that bill: the passive,
after-the-fact view of real traffic, the complement to the active testing
plane (synthetic probes the agent sends on purpose). Network gear exports flow
records to a small collector, `probectl-flow-agent`; the collector decodes
every format into one normalized, **tenant-bound** record (a tenant is one
isolated customer/organization in the deployment, and every record is stamped
with its tenant before anything downstream sees it); the control plane
enriches and stores them in ClickHouse (a column-oriented database built for
high-volume event data); and the API serves the three questions operators
actually ask of flow data: *who are my top talkers, is a link filling up, and
is anything anomalous?*

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  R[routers / switches<br/>NetFlow v5/v9 · IPFIX · sFlow v5] -- UDP --> C[probectl-flow-agent<br/>decode · templates · sampling]
  CL[cloud flow-log exports<br/>AWS VPC · Azure NSG · GCP VPC] -- "local file / object export" --> C
  C -- "probectl.flow.events (FlowBatch, tenant-keyed)" --> B[(bus)]
  C -- "probectl.flow.ingest-quality (bounded receipt, tenant-keyed)" --> B
  B --> P[control-plane FlowConsumer<br/>verify tenant · ASN/geo enrich (opt-in)]
  B --> Q[FlowQualityConsumer<br/>verify tenant + agent · validate allowlists]
  P --> S[(ClickHouse probectl_flows<br/>tenant-first partition + ORDER BY)]
  Q --> PG[(PostgreSQL current receipts<br/>tenant_id + forced RLS)]
  S --> API["/v1/flows/top · /v1/flows/capacity · /v1/flows/anomalies"]
  PG --> APIQ["/v1/flows/ingest-quality"]
```

The path through the code is worth holding in your head, because every other
section is just a zoom-in on one arrow:

1. devices export UDP datagrams to the collector (`internal/flow/collector.go`);
2. the collector decodes them into a normalized `Record` and emits a
   `FlowBatch` on the bus topic `probectl.flow.events`
   (`internal/flow/emit.go`);
3. the control plane's `FlowConsumer` (`internal/pipeline/flow.go`) verifies the
   tenant, optionally enriches ASN/geo, and inserts rows into ClickHouse
   (`internal/store/flowstore/`);
4. the `/v1/flows/*` handlers (`internal/control/flows.go`) run the analytics
   queries, tenant-scoped, against that store.

In parallel, the collector summarizes accepted-packet health into a small
`FlowIngestQualityReceipt`. This is a control receipt, not another copy of flow
analytics: it travels on `probectl.flow.ingest-quality`, is identity-verified by
an independent consumer, and lands as one current forced-RLS PostgreSQL row per
tenant/agent/exporter/protocol.

## Sources

The collector binds three UDP listeners — one socket shared by NetFlow v5 and
v9 (it sniffs the version word in the header), plus IPFIX and sFlow on their own
IANA ports. Disable any listener you don't run.

| Source | Port / input | Notes |
| --- | --- | --- |
| NetFlow v5 | `:2055` | fixed-layout records; sampling interval lives in the v5 header |
| NetFlow v9 | `:2055` | template-based (RFC 3954); shares the v5 socket (version-sniffed) |
| IPFIX | `:4739` | RFC 7011; unknown/enterprise + variable-length fields are skipped by their declared length |
| sFlow v5 | `:6343` | raw-packet-header samples, parsed Ethernet / 802.1Q / IPv4 / IPv6 / TCP / UDP far enough for the 5-tuple |
| AWS VPC Flow Logs | local line export | default v2 text fields; `log-status != OK` rows are ignored |
| Azure NSG Flow Logs | local JSON Lines | Network Watcher v2 flow-tuples are normalized into the same 5-tuple/counter shape |
| GCP VPC Flow Logs | local JSON Lines | Cloud Logging VPC flow entries are normalized from `jsonPayload.connection` |

**Templates (v9 / IPFIX).** Unlike v5's fixed layout, v9 and IPFIX describe
their record shape in a *template* the exporter sends periodically — the legend
mailed separately from the map: until the legend arrives, the symbols on a data
record mean nothing, so the record is undecodable. Data that shows up before its
template is counted as a **template miss** and dropped — the exporter re-sends
templates on its refresh cycle, so the gap self-heals. Template state is keyed
per `(exporter, observation domain)` (the observation domain is the exporter's
own sub-source ID — a line card or engine — so two engines on one box never mix
templates), expires on a TTL (default 30m,
`PROBECTL_FLOW_TEMPLATE_TTL`), and is size-capped (default 4096,
`PROBECTL_FLOW_MAX_TEMPLATES`) so a hostile or misconfigured exporter cannot
grow collector memory without bound.

**Sampling.** High-rate links don't export every flow — they sample (say, 1 in
1000) to keep export volume sane, the way an exit poll asks one voter in a
thousand and multiplies up. A record that represents 1-in-N traffic would
undercount by Nx if you trusted its raw counters, so every `Record` keeps the
**raw exported counters** *and* the sampling rate, and carries pre-scaled
estimates (`bytes_scaled = bytes × rate`, `packets_scaled = packets × rate`)
that all analytics read. The rate comes from wherever each protocol declares
it: the v5 header's sampling field; for v9/IPFIX, the options-template sampler
elements (information elements 34 / 50 / 305) set a per-exporter rate, which an
inline element on the record itself overrides; and an sFlow sample carries its
own. Unsampled traffic is rate 1, so scaling is always safe (it never
multiplies by zero).

## Normalized record and its OpenTelemetry names

All four formats decode into one `Record` (`internal/flow/model.go`), serialized
on the bus as `probectl.flow.v1.FlowRecord`. The schema was modeled on
OpenTelemetry conventions from its first field, so the OTLP layer *exposes* these
signals rather than remapping them. The mapping (see
[`otel-mapping.md`](otel-mapping.md)):

- the 5-tuple uses the standard OTel keys — `source.address`, `source.port`,
  `destination.address`, `destination.port`, `network.transport`
  (`tcp` / `udp` / `icmp`, or the IP protocol number as a string when there's no
  standard name), `network.type` (`ipv4` / `ipv6`);
- flow-specific detail with no OTel home uses the `probectl.flow.*` namespace —
  `probectl.flow.exporter.address` (the device that emitted the datagram),
  `probectl.flow.protocol` (`netflow5` | `netflow9` | `ipfix` | `sflow5`),
  `probectl.flow.interface.in` / `.interface.out`, `probectl.flow.sampling.rate`;
- enrichment uses the ECS-aligned `source.as.number`,
  `source.as.organization.name`, `source.geo.country.iso_code` (and the
  `destination.*` equivalents), because OTel has no AS/geo convention (ECS is
  the Elastic Common Schema — another widely-used naming dictionary).

## Cloud flow logs

Cloud flow-log import lives in `internal/flow/cloudflow`. It is intentionally a
local connector, not a cloud SDK client: an operator points probectl at files or
object-store exports that already exist inside their environment. That keeps the
default no-phone-home posture intact and lets air-gapped deployments use the same
normalization path after they move logs across their boundary.

Every imported row is stamped with the authenticated agent/operator tenant before
storage; tenant identity is never accepted from the cloud log payload. AWS
interface IDs, Azure NSG resource IDs/MACs, and GCP subnetwork labels are kept as
exporter provenance, while `flow_protocol` records which cloud format was parsed.

Use `probectl-flow-agent` in one-shot import mode with
`PROBECTL_FLOW_CLOUD_PROVIDER` and `PROBECTL_FLOW_CLOUD_FILE` (or the equivalent
`cloud_import` YAML block). The agent publishes the normalized records to the
same tenant-keyed `probectl.flow.events` topic and exits; the control plane then
uses the ordinary flow consumer and store path.

## Security posture

Flow export is **plaintext UDP with no authentication — by protocol design**
(the same reality every flow collector lives with). probectl treats it as an
untrusted ingestion surface (see
[`security/threat-model.md`](security/threat-model.md)):

- every datagram or cloud-log line is **untrusted input**: decoders are pure and
	  bounds-checked, record counts, line size, and template state are capped, and
	  malformed input is counted and dropped — never a panic in a production path;
- every enabled UDP listener has an **exporter source ACL** (`allowed_sources` in
  YAML or `PROBECTL_FLOW_*_ALLOWED_SOURCES` in env). Non-loopback listeners
  without an ACL refuse startup, and packets from unlisted source IPs are dropped
  before decode and counted as `source_drops`;
- the tenant on every record comes from the **collector's own tenant binding**
  (its config, the SPIFFE workload identity on its client certificate, or the
  authenticated local import context), never from anything the datagram or cloud
  log claims — source payloads cannot assert which tenant they belong to;
- deploy the collector **adjacent to its exporters** (management network / same
  site) so flow datagrams never cross an untrusted segment;
- everything downstream of the collector rides the standard authenticated paths
  (bus → control plane → ClickHouse over HTTP(S)). The control-plane consumer
  re-verifies each batch's claimed tenant against the agent registry and drops
  unverifiable batches fail-closed.

FX-2's optional canonical evidence channel requires an additional `entity`
plane mTLS certificate for the registered collector and literal exporter IPs
in `evidence.exporters`. Only a successful raw bus batch from an exact listed
UDP source can queue evidence. The separate RPC proves which **collector**
submitted the observation; UDP source IP is still untrusted and does not prove
the exporting device's identity. A current operator source assignment is
required. A context-bound operator anchor resolves the device directly; without
one, a unique current SNMP observation of that exporter address in the same
tenant/context may support the inferred device. The exact supporting evidence
ID is stored and rechecked on every current read. A conflict, expiry or rebind
retires the inference while raw flow remains available.
The evidence worker is one batch deep and sends at most 64 observations per
RPC. A slow or unavailable RPC counts an evidence drop/error without delaying
raw flow delivery. Accepted exporter/domain identity is refreshed after 12
hours, before its 24-hour current-evidence expiry. An unavailable RPC retries
after one minute; a wholly unresolved batch also retries after one minute.
A partly accepted batch retries after one hour so accepted aliases are not
rewritten for every flow packet. Failed and wholly unresolved RPCs do not mark
identity current. A flow record more than 11 hours old stays raw only, so a
delayed timestamp cannot create evidence that expires before the next refresh.
The worker discards stale records before deduplicating exporter/domain keys,
allowing a fresh record later in the same batch to refresh identity. Cloud
flow-log imports never create exporter evidence.

## Enrichment (opt-in)

Raw flow records often lack the AS number and country of an IP — the **AS**
(autonomous system) being the independently-operated network an address
belongs to, like "AS13335, Cloudflare". The
control-plane consumer can fill `source.as.number` / `destination.as.number`,
the AS organization name, and the ISO country code via the opendata enricher —
but it is **opt-in** (`PROBECTL_FLOW_ENRICH_ASN=true`), because the Team Cymru
lookups it uses are outbound DNS and probectl never phones home by default.
Air-gapped deployments can fill the country from local files instead: an
operator-supplied GeoLite2 database (`PROBECTL_FLOW_ENRICH_GEOIP_DB`) or RIR
delegated stats (`PROBECTL_FLOW_ENRICH_RIR_DIR`) enrich with no egress at all,
and `GET /v1/opendata/enrichment?ip=` serves the full merged context (geo,
allocation, IXP presence) for one address — see
[`configuration.md`](configuration.md) for the source-by-source keys.
Device-asserted AS numbers (NetFlow v5/v9/IPFIX can export them) always pass
through and are never overridden — enrichment only fills blanks, is cached, and
degrades gracefully: a down or rate-limited source never blocks ingest.

## Per-exporter ingest quality receipts

“No flows” is ambiguous: the exporter may be quiet, disconnected, sending the
wrong protocol, waiting for a template, or losing records locally. The flow
agent therefore emits the versioned
`probectl.flow-ingest-quality/v1` contract once per reporting window for each
**ACL-accepted** exporter/protocol it has observed.

Each receipt is deliberately small and closed:

- identity: agent, normalized exporter IP, and allowlisted protocol;
- time: bounded window, last accepted packet, and last valid record;
- saturating counters: packets, decoded records, decode-error packets, template
  misses, local queue drops, and local bus-emission drops;
- allowlisted template/sampling state; and
- an honest `healthy`, `degraded`, or `stale` state with a fixed reason and
  fixed safe next action.

The state matrix is deterministic:

| Evidence | State | Safe action |
|---|---|---|
| recent packet + valid record + no observed loss | `healthy` | continue monitoring |
| template missing/learning | `degraded` | verify exporter templates |
| decode failures or no valid records | `degraded` | verify exporter protocol/version |
| local queue loss | `degraded` | reduce local ingest pressure |
| local bus delivery loss | `degraded` | verify the local bus |
| last accepted packet older than three minutes | `stale` | verify exporter delivery |

FX-2's optional entity channel can also submit a `flow.exporter_silent`
signal from this existing stale state. It requires an exact configured
exporter IP and every observed protocol for that exporter to be stale; an
exporter never seen by the collector has no measured silence claim. The
optional fault is suppressed when a protocol window is invalid, a recovery
packet arrived after a queued stale window, or bounded quality-window eviction
made the queued window incomplete. A later complete stale window may signal.
The quality receipt and raw flow bus do not wait on the bounded mTLS fault queue.
Faults carry no tenant, agent, routing-context or canonical-entity selector;
the verified evidence SVID and current operator assignment supply those.

Privacy is structural. Rejected-source addresses never enter the aggregator.
Raw datagrams, decoded five-tuples, credentials, and free-form error strings are
not fields in the protobuf, Go model, migration, API schema, or support-bundle
view. Vocabulary is allowlisted at producer, consumer, and storage edges. Agent
memory is capped at 1,024 exporter/protocol pairs; the tenant store is capped at
4,096 current rows with 30-day cleanup. Counters saturate instead of wrapping.

The bus message is keyed by tenant. The control-plane consumer verifies
tenant+agent binding before persistence; a namespaced lane overwrites a forged
payload tenant with its authenticated lane tenant. PostgreSQL stores receipts
under `tenant_id` with `ENABLE ROW LEVEL SECURITY` and `FORCE ROW LEVEL
SECURITY`, and every query retains an explicit tenant predicate as defense in
depth.

This path is entirely first-party and self-hosted. It adds no external runtime,
dashboard dependency, browser call, or outbound request. The authoritative UI is
the native **Planes → Flow** receipt list, also visible to administrators under
**Admin**.

## Storage

Records land in the ClickHouse table `probectl_flows`, created idempotently by
the flow store (`internal/store/flowstore/clickhouse.go`):

- `PARTITION BY (tenant_id, toYYYYMMDD(ts))` and
  `ORDER BY (tenant_id, ts, exporter, src_addr, dst_addr)` — think one labeled
  drawer per (tenant, day): because the tenant leads
  both keys, a tenant-scoped read prunes at the storage layer — it opens only
  that tenant's drawers and never scans another tenant's data (the tenancy
  guardrail enforced *below* the
  query) — and a single day's parts stay bounded even at NetFlow volumes;
- `PROBECTL_FLOW_RETENTION_DAYS=N` applies a ClickHouse delete-TTL
  (`toDateTime(ts) + INTERVAL N DAY DELETE` — a time-to-live: ClickHouse
  deletes expired rows itself). The default is `90`; `0` disables the TTL and
  keeps flows indefinitely, which the control plane warns about at boot;
- hourly rollups (`probectl_flow_rollups_hour`) are materialized before raw rows
  age out. They keep tenant-scoped lower-resolution bytes/packets/flow counts
  queryable for long-term cost and trend views. Each rollup already retains its
  contributing exporter identity, so observation multiplicity remains
  derivable without a schema migration. A controlled backfill path
  appends still-retained raw inputs for a tenant+window. Stable row identities
  deduplicate repeated inputs. Catch-up never deletes the destination window:
  aged-out raw rows cannot rebuild retained history;
- native Explorer's version6 migration retains complete inputs alongside the
  existing hourly fields. `coverage_version=1` means the original fields and
  timestamps are present. The added exact columns inherit
  `PROBECTL_FLOW_RETENTION_DAYS`; a tighter tenant clock clears them before raw
  deletion. They then report `coverage_version=0`: only the original hourly
  fields and resolution are available. This preserves the prior retention
  default. Explicit `0` remains the keep-forever opt-out;
- query results report their actual source and retained-input coverage. Auto
  uses actual raw coverage and selected resolution, with no fixed day cap.
  Requests for expired raw input, missing historical dimensions or unsupported
  resolution return `flow_query_coverage_unavailable`, never invented zero
  fields or a silently shortened time range. A retention change during a raw
  query triggers a retained-input retry within the original query deadline;
- portability includes raw `flows.jsonl` and, when deployed,
  `flow_rollups.jsonl` with its own `retained_flows` manifest count and coverage
  marker. These physical sources may overlap; their counts are not additive
  traffic totals. Subject export uses the same exact retained identity predicate
  as erasure. Redacted bundles omit the internal `subject_keys` array, which
  duplicates heterogeneous identity values;
- a `memory` store (the default) implements the same `Store` contract for the
  lightweight / single-node deploy, and is the reference implementation the
  ClickHouse SQL must agree with (the two share one local anomaly model, so both
  backends flag identically). The control plane selects the backend with
  `PROBECTL_FLOWSTORE_MODE=memory|clickhouse` (+ `PROBECTL_FLOWSTORE_URL` for
  ClickHouse).

In siloed/hybrid isolation, a per-tenant ClickHouse database holds that tenant's
`probectl_flows` table; the store routes each tenant to its target and **fails
closed** on any routing error rather than landing a siloed tenant's rows in the
pooled table.

## Native flow Explorer (preview)

`POST /v1/explorer/query` accepts the structured `flow` plan advertised by
`GET /v1/explorer/schema`. Tenant scope comes from authentication. Queries
require `ai.query` and `flow.read`; current device interface names additionally
require `metrics.read`. Reusable filters are tenant-owned; changing them
requires `flow.filters.write`. There is no user SQL.

The grammar supports eight grouping dimensions, eight dimensions on each matrix
axis, nested all/any include/exclude filters, and exact decimal statistics.
Selected table and chart detail groups follow deployment query and snapshot
admission rather than a fixed row quota. The selected count fits the existing
Postgres integer metadata representation (2,147,483,647); this is distinct from
the default of 100 detail groups and 5,000-row page granularity. Charts retain 40
plotted groups plus a separate Other series. Matrix columns are ranked within
the selected row population. Time bounds may cover any available retained
history; unavailable historical fields/resolutions produce a coverage refusal.
Execution/read/memory/storage budgets refuse explicitly rather than silently
shortening a query or returning partial statistics.

Filters support equals/not equals,case-insensitive contains/not contains,RE2
match/no match,greater/less than,bitwise AND,CIDR membership and port ranges.
Groups support nested all/any and include/exclude,plus reusable saved filters.
The structural guards are250entries per group,1,000expanded conditions,five
levels and1KiB per regex. These bounds supplement execution and fairness limits.

Metrics include bits/s,packets/s,flows/s,sampling-corrected bytes and packets,
and unique source/destination IPs,ports,ASNs and countries. Each supports average,
p95,p99,maximum and total,with exact decimal text. Charts have one primary and up
to three secondary metrics;additional table selections are bounded by the registry.
Raw bucket widths start at one whole second and may be monthly, yearly or coarser, up to
the signed nanosecond duration representation (9,223,372,036 whole seconds).
The default remains 60 seconds. Retained rollups keep their actual minute/hour
resolution and refuse unavailable finer queries. Existing query cost admission
bounds the work independently of bucket width. Explicit previous periods need not
be adjacent. Longer ranges automatically select retained rollup inputs,or refuse
if the requested fields/resolution are unavailable;the UI reports that coverage.

The deployment operator sets native query cost policy with
`PROBECTL_FLOW_QUERY_*` in the [configuration reference](configuration.md).
The serving process and standalone MCP use the same policy, and REST/MCP schema
discovery reports its current values. These settings do not change selected-row,
dimension or retention reach. Zero is refused at startup. The existing
ClickHouse response-allocation default stays 64 MiB; native flow can use an
explicit, positive operator budget with the same fail-closed sentinel read.

For non-table queries, `total_series` contains source-authoritative bucket
observations over every matching tenant input, independently of selected chart
groups, matrix axes and Other. Each point has an empty group and `other=false`.
Distinct identities are evaluated together in that bucket; adding group unique
counts would overcount identities shared between groups. Absent buckets represent
zero observed matching flow, and the final point carries its actual partial-bucket
duration. Current and previous streams remain frozen across snapshot pages and
replicas. Whole-window `totals` retain the selected statistical calculations;
table queries return an empty `total_series`. The prepared group CSV exports
whole-window totals, rather than a separate bucket-series CSV format.

Table results use shared encrypted, creator-private snapshots. A page contains
up to 5,000 selected groups. `flow_paging` identifies the snapshot, its expiry,
selected-group count, offset and next cursor. Other/totals and chart/matrix
membership describe the complete frozen result. Late ingestion and edits to
saved filters do not change later pages. Continue with only:

```json
{"source":"flow","flow":{"cursor":"<next_cursor>"}}
```

`POST /v1/explorer/compare` uses the same query plus explicit `previous_from`
and `previous_to`. Both periods share selected group and matrix-axis membership;
Other is recomputed from each period's underlying identities. Missing periods
remain missing, rather than becoming zero measurements. Comparison pages count
**groups**, independently of how many metrics each group expands into. Continue
with only `{"query":{"source":"flow","flow":{"cursor":"<next_cursor>"}}}`.
A query cursor cannot be used on the comparison endpoint or vice versa.

Continuation values are opaque control tokens and must be copied unchanged.
Current writers use a letter-only payload/MAC encoding with a non-DNS separator
so mandatory secret/PII/hostname redaction cannot mistake random authentication
bytes for display data. Every result still passes through the same redactor.
Readers also accept intact legacy continuations; older binaries refuse the new
encoding, so coordinate the reader upgrade across control-plane replicas before
using new continuations. Payload canonicality, MAC, creator, tenant, expiry and
current source/permission checks remain mandatory.


`GET /v1/explorer/flow-snapshots/{id}/csv` exports every selected group from the
same frozen result, with explicit `detail`, `other` and `totals` record types.
Single-query metrics are columns; comparison records name the metric/calculation
and exact current/previous/delta/percent values. Empty comparison values denote
a missing period. Exact decimal strings preserve counters above JavaScript's
integer range. Untrusted label cells with formula-like prefixes use a quoted tab prefix
followed by the complete original text, including Unicode, whitespace and controls.
ASCII and full-width formula introducers are covered. Validated numeric metrics
and comparison deltas retain their separate exact decimal representation. Native CSV
record pages also preserve CRLF inside quoted cells; record separators stay LF
and source byte/hash provenance describes the untouched export file. All chunks, current permissions, both periods' input coverage and the
export audit are checked before successful headers. Verify `Content-Length` and
`X-Probectl-SHA256` before accepting a downloaded file.

The CLI shares these operations:

```sh
probectl explorer query --body-file query.json
probectl explorer compare --body-file comparison.json
probectl explorer snapshot-csv <snapshot_id> > flows.csv
```

The CSV client stages and verifies the complete download before writing stdout.
Its default 256 MiB download budget can be set with `--max-bytes`; this is
independent of the generic JSON response byte budget.

Snapshots default to a 15-minute lifetime, bounded further by actual contributing
input expiry, with a 512 MiB tenant cache budget, 128 MiB per snapshot and
64 MiB per encrypted object. They require at-rest encryption, shared Postgres and
object storage, and at least four total Postgres connections for the nested
writer/cache/audit coordination (the deployment default remains 25). Tenant
retention changes, subject erasure and source pruning invalidate derived caches;
ordinary portability exports source flow data and excludes transient cache keys.
A missing, expired or invalidated result requires a fresh query. Snapshots grant
no permission to another owner or tenant, and are not share links.

### Complete saved queries

The preview complete-query API preserves a native plan, metadata/labels,
visibility, time mode, optional previous window and refresh setting. This is
separate from transient result snapshots and the legacy flat inventory views.

```text
GET    /v1/explorer/flow-views
POST   /v1/explorer/flow-views
GET    /v1/explorer/flow-views/{id}
PUT    /v1/explorer/flow-views/{id}
DELETE /v1/explorer/flow-views/{id}?version=<observed_version>
PUT    /v1/explorer/flow-views/{id}/preferences
POST   /v1/explorer/flow-views/{id}/query
```

Create/update bodies contain `definition` and, for updates, the observed
`version`. Versions are decimal **strings**, including above JavaScript's exact
integer range. Create omits the version. Delete uses that same exact text in its
query parameter. A definition contains `name`, `description`, `labels`,
`visibility` (`private` default or `tenant`), `plan`, `time`, optional
`comparison`, and `auto_refresh_seconds` (0,60,90,120). `time.mode=lookback`
requires `lookback_seconds` of at least60; absolute mode uses plan bounds.
`comparison.mode` is `absolute` (explicit `from`/`to`) or `preceding` (the equal
period immediately before the current window). Relative bounds are materialized
from one server clock at execution. A saved definition cannot contain a result
cursor.

Tenant tag fields in a saved flow query require `tags.read`. The server records
each referenced tag's immutable definition ID in the returned `tag_ids` map,
including fields reached through saved filters. Clients do not choose these
IDs. A rename, deletion, replacement under the old key, or a changed saved
filter that introduces another tag makes the view stale and execution refuses
with a conflict; create a refreshed view after reviewing the new definition.
Runs use one tenant tag revision for both comparison periods. A new run applies
current rules to retained history; frozen result pages keep their original
revision and totals.

Reads/runs require `ai.query`, `flow.read` and any joined-field permissions,
including those in current tenant-resolved saved filters. Creating, updating or
deleting additionally requires `flow.views.write`, initially seeded to system
administrators. Only the creator may update/delete; tenant sharing grants
source-authorized reading while preserving ownership. Favorites and recent-open
state are private to each reader. The preference body is `{"favorite":true}` or
`false`; successful run admission records that user's recent-open state.

List filters include `search`, `label`, `visibility`, `owner`, `sort`
(`name`, `created_at`, `updated_at`) and `tab` (`all`, `favorites`, `recents`).
Use `after` and `limit` (1–1000) to follow the explicit `next` cursor. Row and
8MiB response budgets bound a page without concealing later views. Definitions
use the same2MiB grammar-byte budget; view data and private preferences each have
a64MiB per-tenant storage budget. Quota/audit failures refuse atomically.

Run accepts no overrides and dispatches through the existing native query or
comparison service. It returns the same frozen paging and CSV result identity,
with current source/reference permissions rechecked. The same definitions are
available in the native Explorer preview:private/shared view libraries,labels,
favorites,comparison,chart controls and explicit Run. URLs carry the saved
configuration ID,never an authorization grant or a shared result snapshot.

CLI operations are `explorer view-list`, `view-get`, `view-create`,
`view-update`, `view-delete`, `view-favorite` and `view-run`. Mutations take JSON
through `--body-file`; delete takes `--query version=<text>`. Ordinary/subject
portability includes saved configuration, while subject/full erasure deletes
matching views/preferences and preserves sibling tenants.

### Saved chart display

For time queries, `display.time_style` selects `line` (the default),
`stacked_area`, `stacked_columns` or `percent_area`. Each comparison period stacks separately.
The stack adds displayed group observations: unique identities can overlap
between groups, so its height is not a deduplicated global total. A total
overlay remains an independent source statistic. Previous stacks use dashed
outlines. Columns span the source bucket's actual interval, including a partial
final bucket; snapshots missing valid interval metadata require a fresh query.
Column pointer values come from each period's containing source interval;
the readout clock follows the pointer on the aligned current-period axis.
The exact sample inspector, keyboard readouts and CSV keep the original source
values. Logarithmic fill boundaries at zero clip to the plot edge without
changing those observations.

Percentage area uses a linear 0–100% axis. `display.percent_basis` selects
`returned` (default: all returned chart groups, including Other) or `visible`
(the groups currently shown). Hiding groups with the returned basis leaves
their share unpainted; the visible basis recomputes shares. Generated charts
share this same denominator rather than treating each facet as its own total.
Unique identities can overlap across groups, so these are shares of group
observations. Zero or absent denominators have no defined percentage; exact
source zeros remain inspectable. Source total overlays use separate absolute
figures, where saved logarithmic choices still apply. The sample inspector,
keyboard readouts and CSV retain the original source values.
The filled steps follow actual source bucket intervals, including isolated
observations and partial final buckets, and leave undefined intervals empty.
Pointer values select the containing interval independently for each period.
Older results without valid interval metadata require a fresh query.

A complete saved query may include `display`. `total_overlay` draws the
source-authoritative `total_series` over time plots, or the whole-period
`totals` reference on bar charts. Current and previous totals remain separate.
An old frozen result without total-stream metadata requires a fresh query;
the UI does not invent a total by adding group statistics.

Time plots also accept `log_metrics` (selected plotted `measure:calculation`
keys), `sync_axes`, `one_chart_per_series`, `charts_per_row` (1–4, default 1)
and `chart_height` (`short`, `medium`, `tall`; default `medium`). Generated
charts include every visible selected group and Other, with responsive columns.
Logarithmic geometry omits nonpositive coordinates while exact sample tables
and keyboard readouts retain their original values. A plot without positive
values falls back to its complete paged sample table. Synchronized axes use a
shared numeric range; mixed logarithmic/linear metrics use positive bounds and
disclose values outside that range.
Logarithmic grid lines and labels stay spaced for readable short charts;
this does not remove any observations from exact tables or keyboard readouts.

Changing display settings does not rerun a frozen query. Save changes persists
them through the ordinary owner/version/audit checks. Group hide/show/solo
choices remain temporary and do not change snapshots, CSV or independent totals.
These controls apply to bar/time views; matrix and table views retain their own
exact result presentation.

The production-build Chromium gate includes a separate synthetic native-flow
matrix in `native_flow_checks`: bar, line and matrix in both themes at desktop
and touch-mobile sizes. Missing, duplicate or failed cases fail the gate. This
checks rendered behavior and accessibility; authenticated sender/store isolation
requires the separate real-stack proofs.

## Tenant tags and routing contexts

A tenant may define up to 64 tag keys. `GET/POST /v1/tags` list and create
them; `PUT/DELETE /v1/tags/{id}` rename and remove them. Keys cannot shadow
native flow fields such as `tenant_id`, `bytes` or `exporter`. The tenant comes
from authentication. `tags.read` permits listing; `tags.write` is required for
every mutation. A tag change and its audit event commit in one tenant
transaction. Deleting a key also removes its assignments and rules.
Admin → Tenant tags lists stable IDs and keys for the authenticated tenant.
Readers with `tags.read` can inspect the list; only `tags.write` sees create,
rename and delete controls. Delete requires a confirmation that names the
rules and assignments removed. A rename warns that saved flow views using the
old field name will need review.

Rules and assignments name an operator-owned routing context in their path:
`/v1/entity-contexts/{context_id}/tag-rules` and
`/v1/entity-contexts/{context_id}/tag-assignments`. Each collection has
`GET` and `POST`; an item has `PUT` and `DELETE`. Reads page at most 100 rows
with a UUID cursor. Context ABAC runs after tenant authentication and before
forced-RLS storage. Rules can match a canonical CIDR and declared address
side, a bounded RE2 name pattern, or one of the collected SNMP fields
`sys_name`, `sys_descr`, `if_name`, `if_descr`. There is no independent tenant
count quota for definitions, rules or assignments. Writes serialize the tenant
revision and audit event. Complete snapshots, vocabulary listings and derived
fields charge the existing positive query memory profile; deadlines and fairness
admission still apply. An exhausted operation refuses the entire result rather
than truncating metadata. Increase `PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES` and the
associated response/execution profiles for a larger complete workload. The same
flows are available through `probectl tags` commands.
SNMP equality values support the full retained field boundary: 1–1,024 UTF-8
bytes, with significant leading and trailing spaces. Only `sys_descr` admits
tab, carriage return and line feed. Admin's `sys_descr` editor accepts a quoted
JSON string (for example, `"Router\r\nOS\t1"`), so a browser cannot silently
normalize CRLF into LF. The API and CLI JSON bodies use the same escapes;
MCP rule projections preserve it subject to existing egress redaction. Other controls and oversized text are
refused. This input support does not make missing or expired source facts
eligible: a rule matches only when the subject resolver supplies that field.
New SNMP senders preserve raw `sysName` on the signed configured-target
observation separately from its normalized identity alias. Present empty
metadata clears the name; legacy absent metadata may use only a current alias
from the same complete poll. Raw text and an accompanying alias must agree
after identity normalization, or resolution refuses the conflicting facts.
Exact SNMP and name-pattern rules use the retained observational spaces.
Admin → Tenant tag rules selects one owned routing context, pages its rules,
and exposes the same CIDR, RE2 name pattern and collected SNMP field inputs.
Create, edit and confirmed delete require `tags.write`; readers with
`tags.read` see values and order without mutation controls. A rule change
updates fresh queries over retained history at the next tag revision.

Manual assignments refer to a canonical device/interface/prefix, a bound
agent or test, or an operator-owned flow exporter. Exporters are identified
by their registered agent and configured source reference, not by a packet's
claimed agent field. The database checks these references with tenant- and
context-qualified foreign keys. A raw-flow exporter address with multiple current
owners resolves to no tag; an explicit owned pair remains a distinct metadata reference. Manual values take precedence over rules; rules
take precedence over previously reviewed imported suggestions. Imported
assignments remain visible with provenance but cannot be changed through the
manual endpoints. Tag revisions alter current views of retained historical
flows; raw telemetry is never rewritten.
Admin → Manual tag assignments selects an owned routing context and pages
manual and imported values. Operators with `tags.write` can create, edit and
confirm deletion of manual values; imported values are read-only in this
screen. Enter the ID of an already-bound device, interface, prefix, agent or
test. For an exporter, enter its registered agent ID and owned source
reference. The server rejects any target outside the authenticated tenant
and selected context. Readers with `tags.read` see source and value without
mutation controls.

`GET /v1/entity-contexts/{context_id}/resolved-tags` reads current effective
values for one owned subject. Supply `target_kind` and `target_id`; exporters
instead supply `exporter_agent_id` and `exporter_source_ref`. Unknown or repeated
parameters, tenant selectors and caller-supplied facts are refused. The request
requires `tags.read` and the subject's read grant, both with current context ABAC:
`metrics.read` for a device/interface, `entities.read` for a prefix, `agent.read`,
`test.read`, or `flow.read` for an exporter. One FORCE-RLS repeatable-read
transaction binds ownership, tag state and source facts. Ambiguity, memory,
response and time limits fail without a partial result. The existing Explorer
cost policy and tenant query admission apply.

The response contains effective key/value/source, exact decimal-string
`tag_revision` and UTC `as_of`. Revision identifies tag metadata; source facts can
change independently, so the snapshot time is also necessary. Raw addresses,
SNMP, source lineage and encoded exporter identity are omitted. Current
sender/source authorization is required for observational facts. New empty
SNMP polls clear removed names/interfaces/addresses; an expired clearing poll
cannot revive older still-live facts. A later read uses current rules and facts.
Agent CIDR rules use complete local-address metadata attested by the existing
optional site-evidence worker. No hostname or label supplies an address. The
newest site observation fences older sets even after an empty clear, collection
failure, expiry or revocation; contradictory current sets fail closed. These
facts retain the existing evidence lease and current ordinary/evidence identity
and source/context checks. The response still omits raw addresses. Live
canonical-prefix producer and full release/four-store proof remain required;
this read does not by itself complete all flow, alert, report or RCA associations.

A prefix subject can instead have explicit operator `network_prefix` metadata
on its existing canonical entity. Create it with the field or set/clear it with
`PUT /v1/entities/{id}/network-prefix` and the owned `context_id` (an empty
string clears). Admin and `entities network-set` expose the same operation.
CIDR rules match only if they contain the entire explicit range; a misleading
label has no effect. The entity ID and manual assignments survive range edits.
This metadata does not establish a live routing observation. Flow-to-prefix
query associations use the explicit network and owned routing context as
described below. See [prefix network metadata](entity-registry.md#explicit-prefix-network-metadata-preview).

`probectl --json tags resolve CONTEXT --query target_kind=device --query
target_id=DEVICE` returns the same snapshot. Admin → Effective subject tags
resolves on explicit submit and clears results when the subject, context or
signed-in identity changes. Native MCP's user-only `tag_subject_resolve` uses
the same curated projection, subject grants, context checks and egress policy.
No read surface creates an assignment or changes an observed identity.

Flow queries also expose independent `tag.src_prefix.<key>` and
`tag.dst_prefix.<key>` text fields. Each selects the closest explicit canonical
prefix containing that packet address in the uniquely owned exporter's routing
context. A raw sender ID, BGP attribute or prefix label cannot choose that
context or supply a network. Prefix fields require `entities.read` in addition
to `ai.query`, `flow.read` and `tags.read`, with current context policy enforced.

The closest prefix supplies the whole tag set. An unannotated closest prefix
has an empty value; two current canonical IDs for the same closest network are
ambiguous even if their values agree. Neither case inherits a manual/imported
annotation from a broader prefix. A more specific valid child can supply its
own value, and a CIDR rule can cover a subject's entire explicit range. Invalid
addresses and unowned exporters stay unmatched. IPv4-mapped packet addresses
use IPv4 identity; source and destination remain separate. Traffic totals and
row multiplicity are preserved. Both complete raw and retained inputs support
these fields, nested filters, matrices, percentiles, saved identities and frozen
output, subject to the existing tenant query cost policy. This is an explicit
operator-metadata association, not a live prefix producer or routing observation.

An authorized flow query may group or filter by an exact `tag.<key>` text
field. `/v1/explorer/schema` and the native MCP schema include a tenant's tag
keys only for a caller with `tags.read`; querying a tag requires `ai.query`,
`flow.read` and `tags.read`. The returned `tag_revision` identifies the one
tenant tag-rule snapshot used for the query. Both comparison periods use that
same snapshot, and frozen result pages keep the materialized values. Results also retain `tag_tenant_id` and the immutable `tag_ids` for the normalized plan and declared coverage. Native MCP exposes the same IDs with an exact decimal-string revision. Frozen MCP pages and CSV headers use those original identities after a definition rename or deletion; they still require current tenant, owner, source and selected read permissions. Missing or inconsistent identity metadata requires a fresh query. A flow
whose exporter address has no unique, current operator-owned binding has an
empty tag value, shown as **Unmatched** in presentation. The sender's claimed
agent ID never selects a routing context. A later rule edit changes a fresh
query over retained history without changing the stored flow rows or totals.
Tag values also require current `tags.read` and `flow.read` permission on the
owned routing context. Withheld metadata uses the same **Unmatched** value;
selected flow rows and totals are retained. A private saved result binds the
effective context decisions and rechecks the current user before pages,
comparisons and CSV exports. If those decisions change, run a fresh query.
Rule edits alone preserve the saved result's original values and revision.
The receipt binds only subject kinds actually selected by the plan, including
saved predicates. An exporter-only query keeps its `ai.query`, `flow.read` and
`tags.read` minimum; unrelated device/agent grants do not invalidate it. A
selected related subject still requires its current source grant on every read.

Use `tag.device.<key>` for the exporter's operator-owned device anchor and
`tag.agent.<key>` for its registered collecting agent. These are independent
subject values: `tag.<key>` keeps its exporter meaning and does not inherit a
device or agent assignment. Device fields additionally require `metrics.read`;
agent fields require `agent.read`, both globally and on the current context.
Missing, retired or ambiguous owned subjects produce **Unmatched**, preserving
raw flow totals. The raw flow's claimed agent ID never selects these tags.
Rules and manual/import precedence apply within each subject kind. The same
key may be used in all three namespaces in one group, filter or matrix.

REST, CLI, Explorer's schema-driven builder, saved filters/views and native MCP
use these exact names. Saved views pin the immutable tag ID for each qualified
field, so a rename cannot silently retarget a saved query. Only requested
subject kinds load current private facts; all metadata uses the existing query
memory, execution and fairness limits. Current device/agent context grants are
included in saved-result authorization: a grant change requires a fresh query
before pages, comparisons or CSV. This authorization format upgrade also
requires a fresh query for older frozen tag results.

`tag.in_interface.<key>` and `tag.out_interface.<key>` select the input and
output interface index beneath the exporter's owned device. Both require
`metrics.read`. A current attested SNMP interface in the latest complete poll
must establish the index; an old entity, label or assignment alone cannot.
A newer poll that omits the interface withholds its metadata from fresh queries
over history. Zero/missing indices and multiple current canonical interfaces
at the same index are **Unmatched**, including when competing values agree.
The query retains traffic totals. Each side has its own key, so the same tag
can group input and output independently in filters, matrices and saved views.
Frozen input coverage retains both the exporter and the selected index columns;
old hourly summaries without those inputs cannot substitute for complete data. Tagged frozen results can use raw or positively verified complete retained
rollups. Their private version2 source receipt retains the actual source,
complete-input requirement and source-specific input expiry; it refuses unknown
or incomplete rollup coverage. Older private receipts require a fresh query.
These metadata associations do not imply traffic-prefix or test associations.


## Query API (tenant-scoped, `flow.read`)

Four read endpoints, all gated by the `flow.read` permission and scoped to the
authenticated principal's tenant before any value is read (the tenant never
comes from a query parameter):

```text
GET /v1/flows/top?by=<facet>&window=1h&bucket=3m&limit=10&filter=protocol:ipfix&filter=port:443
GET /v1/flows/capacity?exporter=&direction=in|out&window=1h&bucket=3m
GET /v1/flows/anomalies?window=1h&bucket=3m&k=3&min_bps=1000
GET /v1/flows/ingest-quality?agent_id=&exporter=&protocol=&state=&limit=100
```

- **Top-talkers** aggregates the sampling-corrected bytes / packets / flow-counts
  by the requested key and returns the highest contributors (`limit` defaults to
  10, capped at 1000), plus bucketed history for the first six rows so the web
  workspace can show the ranked table and time series from the same query.
  When only one time bucket is present, the chart shows a point with 30 seconds
  of display padding on each side of its actual timestamp. This adds no samples
  and does not imply traffic during the surrounding interval.
  Every ranked row and time bucket also returns `exporter_count`, the number of
  distinct non-empty exporter identities that contributed after the tenant
  boundary and exact-match filters were applied. Empty or whitespace-only
  identities do not become observers; a zero count is disclosed as **exporter
  identity unavailable** in the native UI and CLI. Positive counts are
  described as **observed by N exporters**. It is observation multiplicity
  only: multiple exporters may see overlapping traffic along a path, so probectl does not
  claim the byte, packet, flow, or conversation totals were deduplicated.
  For a positive count on any non-exporter grouping, the native Flow workspace
  offers one **View exporter** / **View N exporters** evidence action. It
  applies that exact row's existing filters and switches the same
  tenant-authorized query to `by=exporter`; the resulting normal table is the
  bounded contributor list.
  Unknown identity and rows already grouped by exporter stay inert. The action
  is local query navigation only—it does not fetch a separate identity list,
  alter totals, or infer duplicate conversations.
  `by` accepts `src`, `dst`, `pair`, `src_asn`, `dst_asn`, `as_name`,
  `src_country`, `dst_country`, `port`, `protocol`, and `exporter`.
  `by=pair` groups source→destination. `as_name` uses the destination AS
  organization with a source fallback; `port` uses the destination service port
  with a source fallback.
- **Narrowing filters** are repeated exact-match `filter=field:value` query
  values and are ANDed. The public `as_name` and `port` filters retain their
  any-endpoint meaning. `group_as_name` and `group_port` instead match the
  destination-with-source-fallback key used by those two groupings; the native
  row and contributor actions use these exact variants so another endpoint
  cannot widen the selected aggregate. The remaining allowlist is every
  grouping except `pair`; use one `src` and one `dst` filter for a pair. The
  authenticated principal supplies tenant scope before filters are
  evaluated—`tenant_id` is not a valid filter. ClickHouse receives every
  filter value as a typed bound parameter; only the allowlisted field enum
  becomes SQL structure.
- **Capacity** buckets per-`(exporter, interface)` throughput into bps/pps
  (bits per second / packets per second) over
  time. `direction` selects which interface (ingress/egress) to group by
  (default `in`); `bucket` defaults to `window/20`, with a one-minute floor.
- **Anomalies** runs the capacity series through the local-default anomaly model
  (`local-zscore-v1`): for each interface, the latest bucket is compared against
  what the model learned from that interface's own preceding buckets — each link
  is judged against its own history, never against other links. The model is
  pluggable, but the default is fully in-process and air-gapped: it makes no
  network calls and refuses to train on features whose `tenant_id` differs from
  the query tenant. It needs at least three training buckets plus the one under
  test. `k` defaults to 3 and `min_bps` to 1000 (so tiny links don't trip). The
  response includes the model name, training-window provenance, the latest
  tenant-local feature vector, and feature citations. The same detector runs over
  both store backends.
- **Ingest quality** returns at most 500 current receipts from the forced-RLS
  PostgreSQL store. State is recalculated at read time, so a stopped agent cannot
  leave a permanently green receipt. `ingest_running:false` means the receipt
  store is not wired (see the centralized
  [limitations ledger](limitations.md#built-not-yet-served-edges)); an empty
  `items` array with `ingest_running:true` means no ACL-approved exporter has
  been observed yet.

## Operations

- The collector logs a stats line every 60s with: packets, records, decode
  errors, template misses, queue drops, emit errors, dropped records (telemetry
  lost after emit retries were exhausted — never silently), and cached
  templates. probectl observes probectl.
- **High-volume tuning.** Raise `PROBECTL_FLOW_READ_BUFFER_BYTES` (the kernel
  socket buffer that absorbs bursts) and `PROBECTL_FLOW_WORKERS` (readers per
  socket) first. Queue overflow is *counted*, not back-pressured: UDP has no
  brakes — senders never wait — so on a UDP
  reader, back-pressure only moves the drop into the kernel, where it's
  invisible. probectl drops
  visibly and keeps a counter instead.
- Decode throughput is gated in CI (`make test-performance` runs
  `TestHighVolumeDecode` without race instrumentation or package contention,
  with a deliberately conservative 50k records/s floor so slow runners stay
  green; real hardware is far above it).

## Example

```bash
# collector (run it near the devices)
PROBECTL_FLOW_TENANT=t-acme PROBECTL_FLOW_BUS_MODE=kafka \
PROBECTL_FLOW_BUS_BROKERS=localhost:9092 ./bin/probectl-flow-agent

# point a device at it (Cisco-style)
# flow exporter EXP destination <collector-ip> transport udp 2055

# ask the API (tenant comes from the authenticated principal, not the URL)
curl -s "https://localhost:8443/v1/flows/top?by=src_asn&window=15m&limit=5"

# CLI parity: pivot, then retain both narrowing filters.
probectl flow top --query by=dst_country \
  --query filter=protocol:ipfix \
  --query filter=port:443
# Human output includes "observed by N exporters" or "exporter identity
# unavailable"; --json exposes the exact exporter_count.

# Inspect bounded, secret-free exporter health without a dashboard dependency.
probectl flow quality --query state=degraded --query protocol=ipfix
```

See [`deploying-agents.md`](deploying-agents.md) for where the collector sits
in the producer catalog (placement, service files, the full
producer-to-first-data path), `deploy/agent/probectl-flow-agent.example.yml`
for the YAML form of every key, and [`configuration.md`](configuration.md) for
the full `PROBECTL_FLOW_*` reference.


Horizon uses five opaque folded bands in equal-height group lanes. The saved
`display.time_style=horizon` and `display.horizon_scale=shared|lane` select a
common amplitude across visible groups (default) or a separate amplitude per
group. Current and previous observations always share their group's amplitude,
including generated facets. Source totals stay on separate absolute figures;
logarithmic settings apply there. The numbered lane legend includes amplitudes;
exact sample inspection, pointer/keyboard values and CSV retain source counts and
previous timestamps. Zero draws a baseline; missing observations leave a gap.
Bands cover actual bucket intervals, including isolated and partial buckets.
The plot grows with lane count to keep labels readable in both themes.

The REST filter and saved-query handlers use typed context services that also
check tenant identity, current permissions and source grants before storage.
Saved queries additionally enforce the authenticated owner or explicit tenant
sharing; favorites and recents belong to each user. The shared service boundary
does not add a new MCP tool: native MCP wiring and protocol proof remain in progress.

### Fresh NetBox tag preview

`POST /v1/entity-contexts/{context_id}/tag-imports/netbox/preview` is a preview
read requiring `tags.read`, `cmdb.read`, the subject's read grant and current
routing-context access. Choose `target_kind` and an exact owned `target_id` for
a device, interface, prefix, agent or test. Exporters use their registered
`exporter_agent_id` / `exporter_source_ref` pair; omitting `target_kind` retains
that input form. The exporter address must have exactly one current owner.
Display labels, caller tenant hints and arbitrary lookup keys never select a CI.

| Subject | Required read grant | Local correspondence |
| --- | --- | --- |
| Exporter | `flow.read` | Current unique registered address and agent/context binding |
| Device/interface | `metrics.read` | Complete current authenticated source IP facts |
| Prefix | `entities.read` | Explicit canonical `network_prefix`, covering the whole range |
| Agent | `agent.read` | Complete current sender-bound address snapshot; hostname is not IP evidence |
| Test | `test.read` | Owned configured IP or DNS host, without DNS resolution |

For example, `probectl tags netbox-preview CONTEXT --body-file preview.json`
can review an explicitly selected NetBox prefix:

```json
{
  "tag_id": "11111111-1111-4111-8111-111111111111",
  "target_kind": "prefix",
  "target_id": "22222222-2222-4222-8222-222222222222",
  "source_id": "101",
  "field": "role"
}
```

`source_id` is optional and is always a positive decimal string: a NetBox
prefix ID for prefixes, otherwise an IP-address CI ID. The server constructs
the endpoint and verifies the selected object still corresponds to a current
private fact. A test's configured DNS host can match an IP CI's `dns_name` or
an unambiguous tenant-owned device/VM name; no DNS query is made. Multiple
addresses auto-resolve only when every mapped candidate names the same
attested parent CI and field value. An unmapped address can be ignored;
ownership errors or different CIs require correction or exact source selection.

Prefixes use their own IPAM role and exact canonical range. Site is available
only from an ID-consistent `dcim.site` scope; a region, site group or location
is not guessed to be a site. Overlapping ranges or VRFs require `source_id`.
No VRF display-name mapping, first-host substitution or routing observation is
inferred. NetBox's own prefix model does not accept `/0`; local manual/rule tag
semantics are independent of that source restriction.

Configure the deployment's NetBox tenant map as described in
[configuration](configuration.md). Source and related device/VM reads freshly
attest that mapped tenant; a brief related-object name is insufficient.
Enrichment caches never authorize import. Missing bindings, outages, source
ambiguity and changed ownership refuse a candidate. Values support 24,000
Unicode code points (96,000 UTF-8 bytes), without control characters. Query
concurrency, execution, memory and response budgets apply; the operation also
has a 15-second deadline and a 4 MiB bound per source response.

The response contains the checked source CI, field, value, provenance and
owned target revision as decimal strings. Private address bags and address
hashes are omitted. The read writes no assignment or canonical identity.
Fixture transport tests are component evidence; the operation remains preview
until its real-service release receipt passes.

In Admin, choose a routing context, tag and subject kind, then enter its exact
ID or registered exporter pair. Only kinds covered by the current read grants
are offered. An optional source object ID disambiguates inventory. Context
discovery requires `entities.read`; otherwise enter an authorized context ID.
Changing an input, context, tag, user, tenant or available subject grants clears
the review. A source failure never substitutes cached enrichment.

With `tags.write` as well, choose **Review NetBox import** and explicitly
confirm the exact value, provenance and tag revision. The server re-attests
the selected CI against current private facts and compares the complete
candidate, including selected field identity and prefix VRF/scope provenance.
After source I/O, it rechecks current context grants, locks the tag revision
and resolves local authority again in an audited tenant write snapshot.
Loss of the selected correspondence, changed source metadata or a changed
revision requires a fresh preview. Unrelated polls or additional unselected
addresses do not expire an unchanged selected relationship. Remote source
requests never run inside the database transaction.

A successful write upserts `source=netbox`, checked provenance and `reviewed_at`
with `tag.assignment.imported` in the same tenant transaction. Manual values
retain precedence. The preview is an operator review, not a stored plan or
signed authorization token, and cannot select a tenant.

The CLI equivalent is `probectl tags netbox-apply CONTEXT --body-file apply.json`.
Use `{"confirmed":true,"preview":PREVIEW_RESPONSE}` with the unchanged complete
preview. Apply requires the same subject read grant plus all three tag/CMDB
grants. Replaying an applied revision is refused; a fresh preview updates the
same imported annotation without duplication. Both operations remain preview
until their real NetBox release receipt passes.

### Tag value and page budgets

Tag values admit 24,000 Unicode code points, including supplementary characters,
with a 96,000-byte UTF-8 bound. Manual and rule writes, reviewed source imports,
query snapshots and flow predicates use the same value reach. Metadata write
bodies are bounded to 384 KiB so JSON-escaped supplementary characters fit;
this does not change the global HTTP or query grammar limits.

Rule and assignment lists return at most the requested 100 rows and also stop
before their encoded items exceed 768 KiB. A shorter page can still carry
`next_cursor`; follow it until absent. No stored rows are dropped or hidden by
that page budget. Admin can disclose the entire value without write permission;
its input counts Unicode points rather than confusing them with UTF-16 units.

Large metadata continues to consume Explorer's lookup, intermediate-group,
response and memory budgets. An oversized operation refuses with the existing
resource-budget error; it never truncates values or returns partial totals.
The schema exposes separate native predicate byte and tag value limits. The
append-only expansion migration and old-silo catch-up preserve tenant RLS,
compound subject FKs and current-rule revision semantics without rewriting data.


### Current tags on synthetic results

The latest-result detail offers **Show current test tags** when the caller has
`tags.read` and `test.read` and the displayed results carry exact
`probectl.test.id` attributes. Target/type matches on legacy results never
supply a tag identity. The view shows the current metadata revision and read
time; refreshing applies current rules, manual values and reviewed imported
suggestions to those earlier results. Probe values and stored labels are
unchanged. A failed refresh clears the earlier disclosure. Long values remain
fully available through the value disclosure control.

`POST /v1/tags/tests/resolve` exposes the same preview read:

```json
{"test_ids":["11111111-1111-4111-8111-111111111111"]}
```

Only exact test references are accepted. Tenant and routing context come from
authentication and current owned state. Both read grants are checked globally
and against each captured routing context. Unknown, unbound, foreign and denied
IDs are omitted without distinction; matching a hostname or address grants no
access. One PostgreSQL RLS snapshot captures ownership, rules, assignments,
context attributes and one `tag_revision`/`as_of`. Repeated references return
one curated subject. The read does not verify a raw sender's test claim.

The CLI is `probectl --json tags tests --body-file tests.json`. The named native
MCP tool is `test_tag_context`, with the same `test_ids` body and the existing
user, consent and audit requirements. Responses carry exact decimal revision
strings and curated key/value/source entries; raw source facts and lineage
are omitted. Values retain the 24,000-character reach. The existing 2 MiB query
request envelope and configured operation, memory, response and fairness
budgets apply to the entire read. An overflow or source failure returns no
partial result. This remains preview pending the complete release-stack proof.

The Ask page also offers this explicit current lookup for metrics that carry an
exact `test_id` and are cited by a resolved headline or finding in the displayed
answer. The answer must belong to the active tenant. The page keeps fetched tags
in that detail only and clears them on a failed refresh or changed answer,
identity or grants. Current annotations are displayed separately from the
original evidence, citations and confidence; they are not added to the model
input or downloaded answer. API and CLI clients can perform the same second
read using the cited IDs; MCP clients use `test_tag_context`. This is the test
evidence context component, with other typed RCA selection and full source
composition still pending.

## Original routing capture references — implementation preview

Flow storage schema 7 can retain an original raw-record digest, a tenant-bound
routing capture key and an exact first processing clock alongside raw and
complete hourly inputs. Captured retries reuse the raw identity even when
open-data enrichment changes. A routing key is an identifier; reading its
retained source evidence requires independent current authorization.
Captured BGP routing metadata requires `events.read` and `entities.read`, in
addition to the query's `ai.query` and `flow.read`, for the current user and
actual credential. Global and original canonical-context permissions are
checked again for queries, frozen readers and reports. A stored receipt cannot
replace a revoked source-plane grant.

Public fallback retains the original source snapshot and each peer view's
independent generation, with an explicit association between them. These IDs
are provenance, never read grants. New associations use immutable capture
format 4; current readers retain formats 1–3 without rewriting their clocks
or identities. Use compatible readers when restoring or downgrading: an
unsupported format is refused rather than decoded as partial routing data.
Verifying a retained manifest does not issue a new source lease; original
expiry and current source authority remain independently checked.

Explorer's shared API, CLI, UI and MCP schema includes source and destination
`bgp_provenance`, `bgp_prefix`, `bgp_as_paths`, `bgp_next_hop_as`,
`bgp_origin_as`, `bgp_first_transit_as` and `bgp_rpki` fields, each prefixed
with `src_` or `dst_`. Complete paths retain their segment boundaries and
values; filter values share the whole-plan byte budget. A blank exact ASN
filter selects unknown independently of ASN zero; `in`/`not_in` lists can
combine blank with complete uint32 values. Nested exclusions retain unknown
traffic unless the predicate actually selects it. When a complete current local RPKI validator export is configured, authenticated
ingestion captures its exact source digest, original generation/expiry, full
covering VRPs and per-path verdicts. Valid/invalid/not_found require that
independent complete source and a known original route origin; AS_SET or
conflicting path verdicts remain unknown. AS0 never authorizes a route. Original
validation is immutable processing-time evidence, so a new validator export or
later expiry does not rewrite past captures. Missing original evidence remains
unknown; older hourly summaries do not reconstruct these fields. Current source authorization applies even when
all selected traffic has unavailable routing metadata.

Older rows and unsupported or unattested sources have no invented capture.
Raw-input expiry clears these references from complete hourly inputs while
preserving the existing hourly aggregates. Tenant export and deletion keep the
same storage-level tenant boundary. The migration extends pooled and routed
tenant stores without changing the checksums of earlier migrations.

The control-plane consumer records these references before enrichment. If raw
ingestion wins the race with the asynchronous evidence worker, its routing
candidate remains private. An exact digest and observed tuple from the existing
issued mTLS evidence channel can finalize that original snapshot, subject to
current sender, source and lifecycle checks. It cannot substitute a newer RIB.
Missing, erased or invalidated evidence stays unavailable. Raw bus publication
never waits for the evidence RPC; optional witness failures and queue drops are
counted in collector statistics.

The outward BGP join remains preview and incomplete. Stored reference support
alone does not establish a physical flow join, a current router path or a
forwarding claim. Readers still require independent current authorization.


## Local IX membership input

The peering-estimate input can load a complete, permitted local PeeringDB
`netixlan` projection with `PROBECTL_FLOW_ENRICH_IX_MEMBERSHIP_FILE`. It is
independent of IX prefixes: a LAN subnet does not establish ASN membership.
Nothing is downloaded. PeeringDB source terms and provider/MSP permission
requirements in [source terms](opendata-aup.md) still apply.

The canonical import format is:

```json
{
  "version": 1,
  "object": "netixlan",
  "observed_at": "2026-11-07T12:00:00Z",
  "complete": true,
  "record_count": 1,
  "data": [
    {"id": 7, "ix_id": 11, "ixlan_id": 13, "asn": 64500, "status": "ok", "operational": true}
  ]
}
```

Include every record in the complete projection; retain inactive statuses and
operational flags. Duplicate IDs, unknown/missing/null fields, invalid IDs or
ASNs, a mismatched count, partial data, future observation clocks and malformed
late rows refuse the whole input. A complete empty array explicitly withdraws
all memberships. Admission covers full bytes, decoding, indexes and copied
results; it does not truncate the population. Refresh by replacing the entire
file and restarting, preserving the true observation time. Reads recheck the
source's enabled state and expiry independently of per-IP cache lifetime.

Only active operational ports can establish the exact ASN + IX + LAN tuple.
Public membership grants no tenant access, owned interface identity, current
route or established peering. The estimate must combine it with current
tenant-owned FX-4 role/interface and routing evidence. This input is preview;
the shared read-only estimate is exposed as a preview; complete real joined-flow, lifecycle and physical-sender qualification remains required.


### Preview peering estimate

`POST /v1/flows/peering-estimate`, `probectl peering estimate`, the typed REST
clients and native `flow_peering_estimate` use the same current-authority
service. The caller needs a current tenant user with `flow.read`, `ai.query`,
`entities.read`, `metrics.read` and `events.read`, including current credential
and context/source restrictions. Tenant and router ownership are never accepted
from the body. The current canonical interface must be on the selected IX LAN
and have an effective IX role, with complete current public prefix and membership
evidence. These inputs establish eligibility, not an operational peering session.

```sh
probectl peering estimate --body-file peering-selection.json --json
```

```json
{
  "context_id": "22222222-2222-4222-8222-222222222222",
  "interface_id": "33333333-3333-4333-8333-333333333333",
  "peer_asn": 64500,
  "ix_id": "71",
  "ix_lan_id": "11",
  "direction": "inbound",
  "from": "2026-11-01T00:00:00Z",
  "to": "2026-11-02T00:00:00Z",
  "bucket_seconds": 300,
  "dataseries": "auto"
}
```

Replace the example identities with owned resources and the public IDs of the
selected exchange. IX/LAN IDs and output counters/rates are exact decimal
strings, including values above JavaScript's safe integer range. No fixed day
cap is applied; retained source coverage and configured finite query admission
remain enforced. The default range is the last hour.

Inbound estimates use the original source-prefix path and ingress interface;
outbound uses the original destination-prefix path and egress interface. Both
router and explicitly labelled public capture paths retain their original
source authority; a newer RIB cannot refill an old capture. The ordinary flow
registry exposes those provenance fields for detailed inspection.

The service retains every owned-router input, including unknown interfaces,
and separately reports eligible, nonmatching, ambiguous and unavailable transit
bytes. It combines all known eligible bytes in each interval **before** p95,
then also reports each transit interface independently. A final partial interval
uses its actual duration. Read `bits_per_second_numerator` /
`bits_per_second_denominator` for the exact rate; never sum per-interface p95s.

Missing observed intervals have no p95. Complete observed inputs describe the
retained query population only, not lossless network telemetry. A known-eligible
p95 with `complete_routing_classification: false` excludes the explicitly
reported unknown volumes. It is neither guaranteed savings nor a forwarding,
routing-policy or live-session claim. The response remains labelled preview
while complete real-source and served-surface qualification is outstanding.

Native MCP preserves exact numeric IX/LAN identities only after current public
evidence proves the complete target. Unavailable targets retain untrusted
caller selections, which remain subject to mandatory text redaction.


## Recorded capacity agreements (preview)

`/v1/flows/capacity/agreements` records complete operator financial terms for
one canonical interface, or one circuit selected by an immutable tag ID and its
complete value. This configuration does not assert that counters are available,
calculate a bill, or grant telemetry access. It is separate from the sampled
capacity series above.

Read with `flow.agreements.read`; create, replace and delete additionally need
`flow.agreements.write`. Only the administrator system role receives these
defaults. A delegated financial reader does not need `flow.read`, and an ordinary
telemetry reader cannot see prices. Current user grants, credential ceiling and
ABAC are read in the same tenant-isolated storage snapshot as the terms.

Create with POST to the collection and a complete `definition`. Replace with
PUT to `/{id}` and the observed exact decimal `version`; replacement appends an
immutable revision. GET `/{id}` returns the head, `?version=1` returns a recorded
revision, and `?at=2026-11-30T23:59:59.999999999Z` selects effective terms. DELETE
`/{id}?version=2` uses the observed head version. Foreign and unknown IDs both
return 404. Inventory retirement preserves financial history without granting
access to the retired source.

The definition requires `name`, `reference`, `valid_from`, `target`, `billing_day`
(1–31), offline IANA `timezone`, `direction`, `currency`, `commit_bps`, `unit_bps`
and `unit_price`. Numeric financial values are exact decimal strings. Interface
targets require `kind: interface`, `context_id` and `interface_id`; circuit
targets require `kind: circuit`, `tag_id` and nonempty `tag_value`. The five
direction conventions are `in`, `out`, `max_directional_percentiles`,
`interval_max` and `interval_sum`. The commit is a commercial term, not a
physical counter-wrap bound or forecast capacity threshold.

The collection and `/{id}/revisions` use `after`, `limit`, `next` and `has_more`.
Revisions page in descending recording order. A default page is 100; larger
complete pages are admitted by configured memory/work resources without a fixed
row ceiling or total-history cap. Retained revisions use
`PROBECTL_FLOW_QUERY_LIBRARY_BYTES`; execution, memory and read-work use the
existing flow-query operation policy. A refusal returns no partial page.

The **Capacity** screen opens this financial configuration independently of
telemetry permissions. It supports exact prices and revisions, interface or
tagged-circuit targets, effective-date lookup, complete catalog/history pages,
and explicit compare-and-delete confirmation. It clears loaded terms on an
identity or permission change and after a current authorization refusal.

The generated Go/TypeScript clients expose all six operations. CLI equivalents:
```sh
probectl --json capacity-agreements list --query limit=1001
probectl --json capacity-agreements create --body-file terms.json
probectl --json capacity-agreements get AGREEMENT_ID --query version=1
probectl --json capacity-agreements update AGREEMENT_ID --body-file revised-terms.json
probectl --json capacity-agreements revisions AGREEMENT_ID --query limit=100
probectl capacity-agreements delete AGREEMENT_ID --query version=2
```


MCP exposes `capacity_agreements_list`, `capacity_agreement_get`,
`capacity_agreement_revisions`, `capacity_agreement_create`,
`capacity_agreement_update` and `capacity_agreement_delete`. These use the same
financial permissions and current tenant/user authorization as REST. A delete
requires the observed exact head revision. Neither the caller nor the arguments
can select a tenant or confer a telemetry grant. Existing MCP consent and full
PII redaction apply to recorded text and prices, so a protected field can be
withheld by redaction. Authorized REST, CLI and the Capacity screen retain the
original financial values. Current canonical target identities and server
revision/cursor metadata keep their exact values.

The capacity calculation path uses retained integer SNMP counters and their
original authenticated poll receipts. Current canonical interface ownership,
source assignments, user grants, credential scope and context policy are checked
before reading history and again before returning measured facts. Reassignment,
revocation or erased receipts invalidate a calculation; another tenant's equal
interface index cannot select its observations.

Its explicit model is `poll_start_counter_poll_mean_overlap`: poll-start clocks
anchor rates, and each proven mean contributes its exact overlap with a
five-minute grid. SNMP poll bounds are not individual OID read timestamps.
Uptime and discontinuity must be present and consistent with the full poll
windows. Resets, ambiguous uptime wraps, overlapping polls and missing coverage
stay unknown. Counter wraps need a unique interpretation under a separately
recorded physical upper bound for the entire requested window. No commit value
or current advertised link speed silently supplies that historical assumption.

The internal source-to-percentile and bill comparison path preserves rational
values, sums distinct circuit members before ranking, and withholds amounts for
incomplete required coverage. This does not yet expose a complete measured
billing or forecast operation on the financial configuration surfaces above.
