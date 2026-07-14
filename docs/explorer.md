<!-- SPDX-License-Identifier: MPL-2.0 -->

# Explorer

Explorer is probectl's shared query workbench at `/explore`. It joins a natural-language
question to a small structured grammar: time, source/plane, dimensions, exact filters,
groupings, measures, visualization, and row limit. The readable preview is the query receipt;
the table underneath always shows exact values even when a visual summary is selected.

ELI5: a recipe is a pre-filled worksheet, not a magic AI prompt. Choosing “Which SLO error
budgets are burning?” fills in `source=slo`, the SLO dimensions, burn measures, and a bar view.
Running it asks the existing SLO engine for the authenticated tenant's rows. The same pattern
covers the ten canonical operator questions in `docs/ux/teardown.md`.

## Query contract

`GET /v1/explorer/schema` returns the fixed catalog of ten recipes. `POST
/v1/explorer/query` accepts an `ExplorerQuery` and returns normalized rows, exact columns, a
readable preview, bounded value suggestions, truncation state, and the native evidence path.
Queries are limited to 500 rows, 12 exact filters, a 90-day time range, and an allow-listed
vocabulary per source. Explorer is intentionally not arbitrary SQL, PromQL, or ClickHouse
syntax.

Supported sources are `flow`, `changes`, `path`, `topology`, `endpoints`, `tls`, `cost`, and
`slo`. Each is dispatched to the production store already used by its native screen. Store
availability follows the documented [deployment limitations](limitations.md); Explorer returns
an honest empty result and never silently substitutes another source.

## Tenant and authorization boundary

There is no `tenant_id` field in `ExplorerQuery`. The server resolves the tenant from the
authenticated principal first, checks `ai.query`, then checks the selected source's existing
read permission. The store call receives that authoritative tenant. Semantic tenant filter
variants such as `tenant`, `tenant_id`, `tenant-id`, and `tenant.name` are rejected.

Value suggestions are calculated from the already-authorized result rows. There is no global
suggestion index to leak another tenant's site, endpoint, service, or certificate names.
Cross-tenant tests insert distinguishable flow rows and prove that both the exact table and
suggestion list stay inside the caller's store partition.

Saved Explorer views reuse `/v1/inventory/views`. That store's outer key is `tenant_id` and its
next key is the authenticated owner. A saved view contains grammar/filter choices only;
opening it reruns the current tenant's telemetry query. A copied foreign view ID is
indistinguishable from a missing ID (`404 saved view not found`).

## Context and evidence

The stable view link contains the recipe, absolute UTC time range, and exact filters. It never
contains tenant identity or credentials. “Open evidence” uses the common short-lived pivot
contract to carry the same time/filter context to the source screen, and “Explain this view”
uses the tenant/RBAC-scoped AI evidence engine. The exact result table remains available beside
both paths so a chart or explanation never hides the source values.

## Operator and CLI examples

```sh
probectl explorer schema
probectl explorer query --body '{
  "question":"Show service dependencies",
  "source":"topology",
  "dimensions":["from","to","kind"],
  "groupings":["kind"],
  "measures":["edges"],
  "visualization":"topology",
  "limit":100
}'
```

The CLI and web client both use the versioned API. Authentication supplies tenant scope; do not
put a tenant selector in the body or URL.
