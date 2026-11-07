# Dashboards and tenant report delivery

The native `/dashboards` screen joins network planes in Operator and Executive
presets. Operator shows detailed plane tables; Executive shows cross-plane
summary, risk, incidents, SLOs and policy. Exact values and coverage notes stay
attached to each view.

Saved-source reporting is preview while complete source, release and surface
acceptance is being qualified. Report delivery uses the local tenant inbox.

## Observation scope and saved recipes

The dashboard time controller supports `15m`, `1h`, `6h` and `24h` in
one `range` query parameter. Reload, Back, Forward and a copied same-tenant link
reproduce that selection. Invalid/repeated values canonicalize to `range=1h`.
Client-supplied tenant parameters are removed; authentication supplies tenant
identity. The controller uses no browser storage.

Flow contributors, capacity, anomalies and synthetic history receive that
duration. Latest-state inventory, topology, alerts, incidents, SLOs, compliance
and detections keep their stated clocks. The page shows tenant name/UUID,
preset, relative selection, actual UTC interval and provenance/coverage receipt.

A saved dashboard is a recipe with one of two data modes:

- **Screen snapshot:** the definition contains absolute observation bounds,
  exact metric strings, provenance, redaction state and coverage notes. Delivery
  preserves those values and bounds. Save another view to change the observation.
- **Saved flow sources:** select exact saved-query references with
  `flow_sources: [{"id":"<saved-query UUID>","version":"<decimal version>"}]`.
  Omit caller `metrics`, `absolute_from` and `absolute_to`. Each query must
  currently be owned or shared in this tenant. Generation resolves its configured
  time mode, executes the complete selected row set, and freezes the actual
  source/comparison intervals and query/filter/tag revisions in the artifact.

Choose **Build from saved flow queries**, then select current queries from the
library. The UI shows pinned versions and clears draft selection when the
authenticated identity changes. A source edit requires an explicit new
selection before generation can use that version.

Reports include tenant scope, source intervals, generation time, generator,
provenance, redaction and coverage notes. Source projection preserves detail,
Other, totals, chart groups/points, total points, both matrix axes/cells and
filter-input identities. Field keys and immutable IDs remain complete; numeric
cells retain exact decimal strings.

## API and current authorization

Every route resolves the authenticated tenant before RBAC/ABAC. Tenant-owned
queries also enforce the storage boundary and explicit tenant predicates.

| Route | Permission | Purpose |
| --- | --- | --- |
| `GET /v1/dashboards` | `metrics.read` | List owned/shared tenant views |
| `POST /v1/dashboards` | `metrics.write` | Save a dashboard recipe |
| `GET /v1/dashboards/{id}` | `metrics.read` | Read an accessible view |
| `GET /v1/dashboards/{id}/manifest` | `metrics.read` | Export a portable recipe |
| `POST /v1/dashboard-manifests/import` | `metrics.write` | Preview or confirm import |
| `GET /v1/dashboard-report-schedules` | `metrics.read` | List owned schedules and destinations |
| `POST /v1/dashboard-report-schedules` | `metrics.write` | Create an owned schedule |
| `PATCH /v1/dashboard-report-schedules/{id}` | `metrics.write` | Pause/resume an owned schedule |
| `POST /v1/dashboard-reports` | `metrics.write` | Generate an immutable inbox artifact |
| `GET /v1/dashboard-report-artifacts` | `metrics.read` | List current-authorized body-free metadata |
| `GET /v1/dashboard-report-artifacts/{id}` | `metrics.read` | Download a verified, audited body |

Sources additionally require current `ai.query`, `flow.read`, applicable
metadata permissions such as `tags.read`, and permission on selected contexts.
Current user grants are intersected with the original credential ceiling.
Stored source requirements describe what a reader must prove; they confer no
permission. Canonical role and routing sources also retain their complete
context lineage; future readers must still hold the applicable `entities.read`
permission and, for role sources, `metrics.read` and `events.read`. Private
version-2 source receipts preserve those requirements alongside compatible
version-1 ordinary/tag receipts in the same tenant-isolated report store.
Routing-backed reports retain every original selector for each comparison period,
including the exact first-capture clock. Later reads recheck those selectors
against current actor, context and source authority; they never re-enumerate
new traffic to replace historical inputs. Complete source requirements use the
existing query workspace for decoding admission and the report store supports
up to 64 MiB of source JSON; resource exhaustion publishes no partial report.

Malformed/unknown-field JSON returns `400`; a manifest above 64 KiB returns
`413`; invalid bounds, duplicate names, kinds or versions return `422`.
Unavailable/private/foreign objects share the `404` shape apart from request
ID. Stale capture returns `409`. Cost, fairness and unavailable-source
refusals publish no partial artifact.

Generation releases its database connection before source work/rendering. One
existing tenant fairness admission and deadline cover the source batch,
projection, staging and publication. Read rows/bytes, response allocation,
workspace and output are charged cumulatively across comparisons, coverage
probes and retries. Missing/malformed ClickHouse cost receipts refuse the batch.
Existing query reach and deployment defaults remain; output never truncates to
fit a budget.

A short publication transaction rechecks the dashboard, lifecycle generation,
current grants/credential/context authority and exact query/filter/tag capture.
It commits metadata, immutable chunks and export audit atomically. A changed
source, subject-erasure invalidation, cancellation, rendering failure or failed
audit leaves no published body.

## Portable manifests, CLI and native tools

The `probectl.io/dashboard/v1` manifest carries name, preset, tenant-local
sharing and redacted disclosure notes. Screen snapshots include absolute bounds
and exact metric pairs. Source recipes contain ordered slots such as
`{"slot":"flow-1"}`, with no local query, tenant, owner or dashboard IDs,
credentials or storage locations.

Bind each slot explicitly to a current destination query in the import request:
`source_bindings: {"flow-1":{"id":"<destination UUID>","version":"<version>"}}`.
Missing, extra, foreign or stale bindings are refused. Validation checks current
destination metadata without fetching telemetry. Preview returns the normalized
recipe and creates no dashboard. Confirmation validates again and derives
tenant/owner from authentication. The preview is stateless.

Terminal commands use the authenticated API and verified TLS:

```sh
probectl dashboard list
probectl dashboard export VIEW_ID > dashboard.json
probectl dashboard import --file dashboard.json --source-bindings-file bindings.json
probectl dashboard import --file dashboard.json --source-bindings-file bindings.json --confirm
probectl dashboard-report generate --body-file report-request.json
probectl dashboard-report artifacts
probectl dashboard-report download ARTIFACT_ID > report.csv
```

Source-free recipes need no bindings file. Bindings use bounded JSON; stdin
remains available for the manifest. The UI exposes the same explicit library
bindings, preview and confirmation. Changing the template clears its prior
preview and bindings.

Eleven native MCP operations reuse these current services:
`report_dashboards`, `report_dashboard`, `report_dashboard_save`,
`report_dashboard_export`, `report_dashboard_import`, `report_schedules`,
`report_schedule_create`, `report_schedule_update`, `report_generate`,
`report_artifacts` and `report_artifact_link`. They retain current grants,
original credential ceilings, consent, audit and bounded typed responses.

An artifact link contains a REST path relative to the operator's API base,
without a token or durable grant. Metadata hashes describe stored expectations;
download independently authorizes and verifies bytes. Binary bodies and stored
source requirements are absent from MCP output.

## Immutable storage, readers and lifecycle

Migration `0061_dashboard_reporting.sql` introduced tenant-owned views,
schedules and artifacts. Migration `0168_dashboard_report_artifact_chunks.sql`
adds ordered 64 KiB Postgres chunks. Complete body admission is operator-configurable
(`PROBECTL_REPORT_MAX_BYTES`, default 256 MiB). Existing
inline bodies retain their 2 MiB representation limit. Larger static PDF/CSV
documents use the same ordered chunk tables with an explicit source-free
document format; 2 MiB is the inline/chunk boundary, not a total report limit.
Static generation, local schedules and verified reads use
`PROBECTL_REPORT_RENDER_MEMORY_BYTES` (default 1 GiB admission, not
preallocation) and `PROBECTL_REPORT_OPERATION_TIMEOUT` (default one minute),
alongside the output row/byte allowances. Operators can raise these positive
profiles for complete workloads. Earlier caller deadlines and cancellation
still win. Effective source output allowance also
depends on the finite operation memory/output policy.

Metadata and chunks have non-null tenant keys, FORCE RLS, tenant-leading indexes
and composite tenant foreign keys. Silo/hybrid catch-up installs equivalent local
relationships and immutable permissions. Metadata/chunk publication shares one
transaction; the migration preserves legacy inline bytes. Older readers fail
explicitly on the new format. Upgrade readers before source-aware publication.

The global tenant registry stays provider-only. Its transaction-scoped identity
function exposes only the current tenant's name and slug.

Download checks current source ownership/sharing, actual credential ceilings and
captured/current context grants before body I/O, then again in the final audited
transaction. Later query/tag edits do not replace frozen values. Current
visibility or grant changes can still withdraw access.

The reader stages one coherent tenant snapshot and verifies every chunk ordinal,
complete byte count and independent full-body hash before success headers or
attachment bytes. Missing, extra or corrupt chunks produce no body. Legacy
inline bodies use the same verified path. Responses carry exact
`Content-Length`, `X-Report-SHA256`, a strong `ETag`,
`Cache-Control: no-store` and `nosniff`. Request-owned staging is bounded,
sealed only after complete success and cleared on close.

The inbox pages all retained owned/shared report metadata. The default page
contains up to 200 currently authorized items; `limit` can request a larger
positive page within operation memory, response and deadline admission.
`next_cursor` continues from already-visible metadata, bound to the current
caller and tenant. Hidden source identifiers never become a public cursor;
each page rechecks current source access. Metadata lists load no report body.
Budget refusal returns no partial page. The UI exposes older/newer pages, the
CLI accepts `dashboard-report artifacts --query limit=250 --query cursor=...`,
and native `report_artifacts` accepts the same `limit`/`cursor` inputs.

Subject portability includes reports generated by that subject or owned through
its same-tenant schedule. Subject erasure conservatively invalidates all
source-aware derived reports in that tenant because opaque documents cannot
prove absence of the erased subject. It fences in-flight captures before source
cleanup, and its receipt verifies chunk removal. Static documents retain
generator/schedule-owner matching; unrelated static documents keep their complete
bytes. Tenant erasure cascades through views, schedules, artifacts and chunks.

## Scheduling and audit

Core configures `tenant-report-inbox` with `outbound_default: false`.
Unknown destinations fail validation; the UI requires a ready destination.

Create/resume of a source schedule proves the current caller's credential can
execute every selected source. This bounded preflight runs outside publication,
discards its rows and retains fairness admission through final configuration,
lifecycle and grant checks. Pausing delegates no source read.

The existing scheduler independently reloads the owner's current read-only
background authority. It asserts no interactive MFA; a current-MFA requirement
cannot silently become a background grant. Source recipes execute their pinned
queries for each delivery; screen snapshots retain their stored observation.

Publication rechecks ownership, sharing, enabled state and exact due state.
Artifact creation, next-run advance and audit commit together. A competing pause,
edit, revocation or delivery discards the obsolete render. An overdue schedule
delivers once and advances beyond now. Rendering/storage/audit failure leaves
the schedule due.

The tenant hash chain records `dashboard.save`,
`dashboard.manifest_export`, `dashboard.manifest_import`,
`dashboard.report_schedule`, `dashboard.report_schedule_update`,
`dashboard.report_export`, `dashboard.report_delivery` and
`dashboard.report_download`. Payloads contain IDs, format, destination and
redaction state. Artifact bytes and exact telemetry values stay out of audit
payloads.

## Required verification

The default general renderer profile supports 500,000 logical CSV rows and 4,000 PDF rows.
`PROBECTL_REPORT_CSV_ROWS` and `PROBECTL_REPORT_PDF_ROWS` configure source
publication capacity; they are positive workload admission settings.
At defaults, source publication reserves 1,000,000/8,000 logical records respectively so
identity, filters, totals and other metadata are charged alongside detail.
Generation, schedules, projection and verified downloads share the configured
output policy. Renderer workspace uses the configured query-memory quarter
share; staging uses half, with slice/hash/final-chunk overhead charged before
allocation. Raise the operation memory budget with output bytes, and provision
that capacity at the selected tenant concurrency. Serialized size is checked
against the chunk ordinal representation (2^31 chunks); that representation
bound is not a tested capacity or an allocation promise. Real CI separately
requires complete above-default CSV/PDF rows and full paired-tenant body
write/read/hash checks beyond the former 256 MiB limit. Existing corruption,
missing/extra-chunk, lifecycle, old-reader and foreign refusal controls remain.
Byte, memory, deadline and cumulative source-read admission still apply.

Required CI includes paired Postgres/ClickHouse sources, complete 500,000-detail
CSV from ten disjoint 50,000-row queries, independent streamed CSV/digest parsing,
one generation lane through the compiled CLI with a matching finite request
timeout and the other through the API client (the same single POST per tenant),
and independent extraction of actual 4,000-detail source PDF output. The large
fixture reserves a full standalone response, intermediate-group and interface
allowance for each source before the batch divides retained capacity. Its
recorded ten-source operator profile uses 120 seconds, 16 GiB operation memory,
640 MiB response bytes, 50 million cumulative read rows, 8 GiB cumulative read
bytes, 5 million intermediate groups and 100,000 interface items. These are
workload admission settings, not immutable product maxima. Deployments can
configure the same profile through `PROBECTL_FLOW_QUERY_TIMEOUT`,
`PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES`, `PROBECTL_FLOW_QUERY_MAX_RESPONSE_BYTES`,
`PROBECTL_FLOW_QUERY_MAX_READ_ROWS`, `PROBECTL_FLOW_QUERY_MAX_READ_BYTES`,
`PROBECTL_FLOW_QUERY_MAX_INTERMEDIATE_GROUPS` and
`PROBECTL_FLOW_QUERY_MAX_INTERFACE_ITEMS`. Provision matching control-plane and
ClickHouse capacity and tenant concurrency for the selected workload; size the
profile upward when complete required results need it. No result is shortened
to fit an earlier budget. The profile's runtime qualification is recorded by CI;
these configured ceilings are not a measured peak-memory claim.
Complete field IDs, exact integers, Unicode, formula safety, nested filters,
comparison and matrix sections remain required.

The offline Go PDF renderer uses bundled hash-verified Noto fonts and shapes
complex scripts/bidirectional text. Logical Unicode accompanies visible glyphs.
Unsupported glyphs, invalid records and exhausted budgets refuse the document.
CI-only Poppler verifies extraction, page bounds and raster output; an adversarial
replacement-Unicode case must fail independently. Offline Chromium font-reference
images supplement those checks. These tools are absent from the product runtime.

Isolated-process receipts distinguish charged staging allocation from Linux
peak RSS, including renderer/runtime/verifier overhead. Source generation also
records heap observations. Durations are observations; finite resource policies
remain enforced.

The native-flow real-service receipt drives collector-derived data, compiled CLI,
TLS MCP and signed-in Chromium in both themes through source selection,
generation and explicit destination binding. It verifies exact counters, frozen
bytes and source-removal withdrawal. Development bus/TSDB transports and
generated-protocol provenance remain explicit.

The release-image E2E separately uses registered collectors over verified
TLS/SASL Kafka, the HTTPS ClickHouse reader, encrypted filesystem snapshots,
Postgres report publication, TLS MCP consent/current-link controls and real
Dex-authenticated Chromium source selection/native binding in both themes.
Paired API/compiled CLI refusals and restart survival remain required. Its real mTLS agent to authenticated TLS Prometheus leg remains
mandatory. Generated inputs do not establish hardware-exporter behavior.
Receipts require successful execution on the candidate; source checks alone do
not qualify the feature.
