# Dashboards and tenant report delivery

The `/dashboards` screen is the dense, first-party view for joining probectl's
network planes. It has two presentation presets—**Operator** and **Executive**—but
both presets keep the evidence visible: exact values remain tables, charts share
one absolute UTC interval, and coverage gaps stay attached to the view.

Think of a saved dashboard as a sealed recipe card. The card records which
tenant it belongs to, who owns it, the absolute time range, the exact values the
authorized browser saw, provenance, redaction state, and known blind spots. A
report renderer can turn that card into PDF or CSV without contacting another
service.

The portable manifest is a deliberately smaller recipe card. Its stable
`probectl.io/dashboard/v1` document contains only the name, preset, same-tenant
sharing choice, bounded absolute interval, disclosure notes, and exact metric
name/value pairs. It cannot carry a tenant ID, owner ID, dashboard ID,
credential, storage locator, or creation/update timestamp. The bounded
`absolute_from` / `absolute_to` observation interval remains part of the recipe.
Export removes known tenant/owner identifiers and applies the native telemetry
secret/PII redactor before bytes leave the API.

## Scope shown in every view and artifact

The page keeps these facts visible above the panels:

- tenant display name and immutable tenant UUID;
- Operator or Executive preset;
- absolute `from` and `to` timestamps in UTC;
- the coordinated chart window;
- an expandable receipt for provenance, redaction, and coverage limitations.

Every generated PDF/CSV repeats the same contract and adds generation time and
generator identity. A report is rejected before storage if any mandatory field
is absent. This prevents a chart from becoming an apparently universal claim
after its tenant or observation window is separated from it.

## API and authorization

All routes resolve tenant identity from the authenticated principal before
checking RBAC. The browser never sends `tenant_id`.

| Route                                     | Permission                       | Purpose                                                     |
| ----------------------------------------- | -------------------------------- | ----------------------------------------------------------- |
| `GET /v1/dashboards`                      | `metrics.read`                   | List views owned by the caller or shared inside this tenant |
| `POST /v1/dashboards`                     | `metrics.write`                  | Save a bounded dashboard definition                         |
| `GET /v1/dashboards/{id}`                 | `metrics.read`                   | Read an owned/shared view; foreign IDs look missing         |
| `GET /v1/dashboards/{id}/manifest`        | `metrics.read`                   | Export a deterministic, redacted native JSON manifest       |
| `POST /v1/dashboard-manifests/import`     | `metrics.write`                  | Preview or explicitly confirm a strictly validated import   |
| `GET/POST /v1/dashboard-report-schedules` | `metrics.read` / `metrics.write` | Inspect configured destinations or create a schedule        |
| `POST /v1/dashboard-reports`              | `metrics.read`                   | Generate a PDF/CSV artifact in the tenant inbox             |
| `GET /v1/dashboard-report-artifacts`      | `metrics.read`                   | List artifact metadata without loading binary bodies        |
| `GET /v1/dashboard-report-artifacts/{id}` | `metrics.read`                   | Audited artifact download                                   |

Malformed or unknown-field JSON is `400`; a manifest over 64 KiB is `413`;
semantically invalid bounds, duplicate metric names, kinds, or versions are
`422`. A missing, private, or cross-tenant object is the same `404` shape
(apart from the unique request ID), so an identifier cannot be used to
discover another tenant's objects.

Import is two-step:

1. Send `confirm: false`. The server validates every bound, runs redaction
   again, returns the canonical manifest plus a preview, and creates no row.
2. After a human reviews that preview, send its returned manifest with
   `confirm: true`. The server generates a fresh ID and derives tenant and owner
   from the authenticated request before the forced-RLS insert.

The preview is intentionally stateless. There is no import staging table,
background service, external dashboard engine, or outbound call.

The same operations are available from the terminal surface:

- `probectl dashboard list|create|get` manages saved views;
- `probectl dashboard export <id> > dashboard.json` writes the redacted native
  manifest to standard output;
- `probectl dashboard import --file dashboard.json` previews without creating;
- `probectl dashboard import --file - --confirm < dashboard.json` explicitly
  creates after validation;
- `probectl dashboard-report schedules|create-schedule|generate|artifacts`
  manages the local report inbox; and
- `probectl dashboard-report download <id>` streams the audited PDF/CSV bytes to
  standard output, so an operator chooses the destination explicitly.

Requests use the authenticated session's `--tenant` scope; no command accepts
`tenant_id` in a request body.

## Storage isolation

Migration `0061_dashboard_reporting.sql` creates three tenant-owned tables:

1. `dashboard_views` stores the saved definition.
2. `dashboard_report_schedules` references a view through
   `(tenant_id, dashboard_id)`.
3. `dashboard_report_artifacts` references its view and optional schedule
   through composite tenant keys and caps binary content at 2 MiB.

All three tables have non-null `tenant_id`, tenant-leading indexes, `ENABLE ROW
LEVEL SECURITY`, and `FORCE ROW LEVEL SECURITY`. Store queries also carry an
explicit tenant predicate. That is two locks on the same door: the query asks
for one tenant, and PostgreSQL refuses to reveal any other tenant even if a
future query forgets.

The global `tenants` registry remains provider-only. Migration
`0062_current_tenant_identity.sql` exposes only the current transaction's name
and slug through a `SECURITY DEFINER` function bound to
`probectl.tenant_id`; it does **not** grant the application role permission to
enumerate the registry.

Tenant deletion cascades through views, schedules, and artifacts. Artifact list
queries return metadata only; loading bytes is a separate audited action.

## Scheduling and delivery

Core ships one configured destination: `tenant-report-inbox`.

- It is local PostgreSQL storage, not an email address or webhook.
- `outbound_default` is always `false`.
- An unknown destination fails validation; the scheduler never guesses an
  endpoint.
- The UI disables scheduling when no configured destination is ready.

The control-plane singleton `dashboard-report-scheduler` scans active tenant
registry metadata, then opens a **separate RLS transaction for each tenant**.
Due rows are selected with `FOR UPDATE ... SKIP LOCKED`, which makes HA workers
safe: only one worker owns a schedule in a transaction. It renders the bounded
saved definition, stores the artifact, advances the next daily/weekly/monthly
run beyond the current time, and appends `dashboard.report_delivery` atomically.
Missed intervals are collapsed into one current delivery rather than replayed
as a burst.

Scheduled artifacts intentionally preserve the saved dashboard's absolute
observation interval and values. `generated_at` tells when delivery happened;
`absolute_from`/`absolute_to` tell when the evidence was observed. This is a
repeatable evidence snapshot, not a claim that old values were freshly sampled.
Save a new view when the intended observation interval changes.

## Audit events

The tenant hash chain records:

- `dashboard.save`;
- `dashboard.manifest_export`;
- `dashboard.manifest_import` with `confirmed: false|true`;
- `dashboard.report_schedule`;
- `dashboard.report_export`;
- `dashboard.report_delivery` (actor `probectl-report-scheduler`);
- `dashboard.report_download`.

The audit payload carries IDs, format, destination, and redaction state—not
artifact bytes or exact telemetry values.

## Operator checks

```sh
cd web
npm test -- src/test/dashboards.test.tsx src/test/dashboard-reporting.test.tsx

cd ..
GOCACHE=/private/tmp/probectl-gocache go test ./internal/control ./internal/store \
  -run 'Test.*Dashboard.*Tenant|Test.*DashboardManifest|Test.*Report.*Tenant|Test.*Export.*Audit' -count=1

GOCACHE=/private/tmp/probectl-gocache go test ./internal/cli \
  -run 'TestCLIDashboardManifest' -count=1

PROBECTL_DATABASE_URL='postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable' \
GOCACHE=/private/tmp/probectl-gocache go test -tags=integration ./internal/control ./internal/store \
  -run 'TestDashboardManifestRoundTripAndTenantIsolation|TestDashboardExportAuditAndTenantIsolation|TestDashboardReportTenantIsolation' -count=1
```

If scheduled delivery stops, check the singleton coordinator and search the
tenant audit stream for the last `dashboard.report_delivery`. Renderer/storage
failure leaves the schedule due and commits neither a partial artifact nor a
misleading audit receipt.
