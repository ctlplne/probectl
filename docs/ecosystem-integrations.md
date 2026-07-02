# Ecosystem integrations — Grafana, Prometheus, CMDB, cloud metrics

## What this is

probectl is built to **slot into the observability stack you already run**, not
to demand you rip it out and start over. Three integrations make that real:

- **Grafana** (the open-source dashboarding tool) queries probectl directly, as
  if probectl were a Prometheus.
- **Prometheus** (the de-facto open-source metrics database, which collects by
  *scraping* — periodically fetching metrics over HTTP) either scrapes metrics
  out of probectl (**federation** — one metrics system serving selected series
  for another to scrape) or pushes metrics into it (**remote-write** —
  Prometheus's standard push protocol).
- **ServiceNow or NetBox CMDB** correlation links probectl incidents and assets
  to your existing configuration items (a **CMDB** is a configuration
  management database — the organization's asset inventory; a **CI**,
  configuration item, is one tracked asset in it).
- **Cloud metric import** turns local/exported AWS CloudWatch, Azure Monitor,
  and Google Cloud Monitoring rows into tenant-scoped probectl metrics without
  polling cloud APIs.

The metrics surfaces live in `internal/promapi`; the CMDB clients live in
`internal/cmdb`; the local cloud metric importer lives in
`cmd/probectl-cloud-metrics` and `internal/cloudmetrics`. The native Terraform
provider lives in `cmd/terraform-provider-probectl` and
`internal/terraformprovider`.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  G[Grafana] -- "Prometheus datasource API\n/v1/grafana/api/v1/*" --> P[probectl control plane]
  Prom[Prometheus] -- "scrape /v1/prometheus/federate" --> P
  Ext[external Prometheus / agents] -- "remote-write /v1/prometheus/write" --> P
  Cloud[local cloud metric exports] -- "probectl-cloud-metrics\nremote-write" --> P
  P -- "read-only CMDB lookups (TLS)" --> SN[ServiceNow / NetBox CMDB]
  P --- T[(TSDB: probectl_* series)]
```

## The tenant boundary (read this first)

The dangerous part of exposing a metrics query API is that a query language is
powerful enough to ask for *anyone's* data. probectl closes that hole by
enforcing **tenant first, then RBAC** (role-based access control — the caller's
permission set) on every surface here (the tenant-isolation
rule in the [Non-negotiables](../CONTRIBUTING.md#non-negotiables)):

- **Only plain series selectors are accepted** — `metric{label="value",...}`, a
  metric name plus label filters. The rest of PromQL (Prometheus's full query
  language) — functions and operators — is rejected outright, because *a query
  probectl cannot fully parse is a query it cannot tenant-scope.* (The parser in
  `internal/promapi/selector.go` returns an explicit error for anything beyond a
  selector.)
- **The tenant is forced, not trusted.** Whatever `tenant_id` matcher the caller
  wrote is **removed**, and a single `tenant_id="<caller's tenant>"` equality is
  injected (`ForceTenant`) — the bank teller ignores whatever account number you
  wrote on the slip and uses the one on your ID. In `PROBECTL_TSDB_MODE=prometheus`
  mode, only the
  canonical reconstructed selector is forwarded upstream — never the caller's
  raw text.
- **Remote-write payloads are untrusted:** size/series/sample/label caps apply,
  and every incoming sample's `tenant_id` label is **forced** to the caller's
  tenant.
- **RBAC** sits on top: reads need `metrics.read`, remote-write needs
  `metrics.write`, CMDB lookups need `cmdb.read` (permissions added in migration
  `0022_metrics_cmdb_permissions.sql`).

## Grafana datasource

probectl exposes a Prometheus-compatible API subset at `/v1/grafana`, so you add
it to Grafana **as a Prometheus datasource** — no plugin to install:

1. Connections → Data sources → Add → Prometheus.
2. URL: `https://<probectl>/v1/grafana`. Set the HTTP method to POST.
3. Attach credentials for a probectl principal holding `metrics.read` (in dev
   mode, none needed).
4. "Save & test" — probectl answers Grafana's `buildinfo` and `1+1` health
   probes.

Provisioning-as-code lives at
`deploy/grafana/provisioning/datasources/probectl.yml`.

The available endpoints, all under `/v1/grafana/api/v1/`: `query`, `query_range`
(GET and form-POST, the way Grafana actually sends them), `series`, `labels`,
`label/{name}/values`, `status/buildinfo`, `metadata`. Range queries return the
**raw stored samples** in the window (no step interpolation) — use Grafana
transformations for any client-side math. The metric catalog is the
`probectl_*` namespace (results, devices, flows, BGP, threat — whatever the
pipelines land in the TSDB).

**Two modes:** with the in-memory TSDB (lightweight mode) queries evaluate
in-process; with `PROBECTL_TSDB_MODE=prometheus` the canonical selector is
forwarded to the backing Prometheus/VictoriaMetrics and the response passes
through.

## Prometheus federation (probectl → Prometheus)

`GET /v1/prometheus/federate?match[]=<selector>` serves the **latest sample**
of every matching series in the Prometheus text exposition format (the
plain-text `name{labels} value` lines a Prometheus scrape expects) — drop it
into a Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: probectl
    honor_labels: true
    metrics_path: /v1/prometheus/federate
    params:
      "match[]": ["{__name__=~\"probectl_.*\"}"]
    scheme: https
    static_configs: [{ targets: ["probectl.example.com"] }]
```

**Cardinality guard:** cardinality is the number of distinct series — every
unique label combination is one more. A scrape matching more than the series cap
(`DefaultMaxSeries`, 5000) **fails closed** with an explicit error rather than
melting the scraper — narrow the selector. This is the thing to watch for when
federating: an over-broad `match[]` is rejected on purpose, not silently
truncated.

## Prometheus remote-write (external → probectl)

`POST /v1/prometheus/write` accepts the standard snappy-compressed protobuf
`WriteRequest` (snappy — a fast compression format; protobuf — a compact binary
encoding; together, the remote-write wire format), so an existing Prometheus
(or vmagent / Grafana Alloy) can push metrics **into** probectl:

```yaml
remote_write:
  - url: https://probectl.example.com/v1/prometheus/write
    # credentials for a principal holding metrics.write
```

Ingested samples land in probectl's TSDB tenant-tagged (the `tenant_id` is forced
to the caller's tenant on decode) and immediately become queryable and alertable
just like native series.

## Cloud metric import

`probectl-cloud-metrics` is the local connector for cloud metric exports. It
accepts newline-delimited JSON records from the operator's own export pipeline
and posts snappy-compressed Prometheus remote-write to the self-hosted control
plane:

```bash
export PROBECTL_API_URL=https://probectl.example.com
export PROBECTL_TENANT=00000000-0000-0000-0000-000000000001
export PROBECTL_API_TOKEN="$TOKEN"

probectl-cloud-metrics \
  -provider aws_cloudwatch_export \
  -file /var/lib/probectl/imports/cloudwatch.jsonl
```

Provider values are `aws_cloudwatch_export`, `azure_monitor_export`, and
`gcp_cloud_monitoring_export`. The importer never fetches AWS, Azure, or Google
APIs by itself. Any `tenant_id` field in the input file is ignored; the emitted
remote-write request is authenticated and tenant-bound by the API header, and
the control plane forces `tenant_id` again when decoding remote-write.

## CMDB correlation

This links probectl's view of the network to your system of record for assets.
It is **read-only**: probectl looks up CIs and never writes to the CMDB.
Configure either provider via environment variables:

```bash
export PROBECTL_CMDB_PROVIDER=servicenow
export PROBECTL_CMDB_URL=https://acme.service-now.com
export PROBECTL_CMDB_SECRET='integration-user:password'   # env only, never logged
# optional: PROBECTL_CMDB_TABLE=cmdb_ci  PROBECTL_CMDB_CACHE_TTL=10m
```

```bash
export PROBECTL_CMDB_PROVIDER=netbox
export PROBECTL_CMDB_URL=https://netbox.example.com
export PROBECTL_CMDB_SECRET="$NETBOX_READ_TOKEN"           # env only, never logged
```

Surfaces:

- `GET /v1/cmdb/lookup?key=<ip|hostname>` — direct lookup.
- `GET /v1/incidents/{id}/cis` — the incident's target plus its signal targets,
  resolved tenant-scoped and correlated to CIs with deep links.
- `GET /v1/agents/{id}/ci` — asset correlation by agent hostname.

**Behavior:** ServiceNow lookups hit the Table API with an encoded disjunction
query (`ip_address=<k>^ORfqdn=<k>^ORname=<k>` — "match the key as an IP, *or* a
fully-qualified domain name, *or* a name"). NetBox lookups hit the IPAM,
device, and VM API endpoints for the same canonical key. Both providers are
capped at 10 CIs per lookup (`maxCIsPerLookup`) over verified TLS (the
`PROBECTL_CMDB_URL` must be HTTPS; plain `http` is allowed only for loopback test
instances).
Results — including misses — are TTL-cached (each cache entry expires after its
time-to-live), so **a down CMDB serves stale cache
and never breaks core function** — the same read-only, cached, degrade-gracefully
discipline probectl applies to every external source. Keys are canonicalized
(case, ports, schemes), and non-keys (CIDR prefixes, free text) are dropped
before a query is ever made.

**Multi-tenant note:** the CMDB endpoint and credential are deployment-level —
one CMDB connection for the install. Correlation *requests*, however, are
tenant-scoped: a caller can only correlate its own tenant's incidents and
agents. Per-tenant CMDB configurations would ride the per-tenant secrets work
and are not part of this integration today.

## Testing

`go test ./internal/promapi ./internal/cmdb ./internal/cloudmetrics ./internal/terraformprovider ./internal/control ./cmd/probectl-cloud-metrics ./cmd/terraform-provider-probectl` covers the
strict selector grammar (including injection attempts), tenant forcing,
instant/range/labels/series evaluation, cardinality caps, federation exposition,
remote-write decode limits plus tenant forcing, the full Grafana request
sequence against a seeded TSDB (renders plus cross-tenant leak canaries), the
RBAC route declarations and their 401s, the ServiceNow and NetBox
client/resolver paths against `httptest` doubles (cache, stale-serve, negative
cache, correlation), the cloud metric importer through the same remote-write
decoder served by `/v1/prometheus/write`, and the Terraform provider's
tenant-scoped CRUD/header behavior against `httptest` doubles.
