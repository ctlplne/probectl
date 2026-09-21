<!-- SPDX-License-Identifier: BUSL-1.1 -->

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
readable preview, bounded value suggestions, truncation state, the native evidence path, and a
sanitized logical execution receipt. Queries are limited to 500 rows, 12 exact filters, a
90-day time range, and an allow-listed vocabulary per source. Explorer is intentionally not
arbitrary SQL, PromQL, or ClickHouse syntax.

Supported sources are `flow`, `changes`, `path`, `topology`, `endpoints`, `tls`, `cost`, and
`slo`. Each is dispatched to the production store already used by its native screen. Store
availability follows the documented [deployment limitations](limitations.md); Explorer returns
an honest empty result and never silently substitutes another source.

### Period comparison

`POST /v1/explorer/compare` accepts the normal query as the current absolute window plus
explicit `previous_from` and `previous_to` bounds. The server normalizes both windows, applies
the same authenticated tenant and source permission to both reads, and aligns numeric measures
by the selected groupings. The response contract is identified as
`explorer-comparison/v1`.

ELI5: this is two copies of the same local worksheet with different clocks. The server reads
both from the same tenant drawer, lines up matching labels, and shows current, previous,
absolute delta, and percent change. A previous value of zero is `zero_baseline`; a missing
side is `missing_current` or `missing_previous`. These states remain undefined instead of
quietly turning missing evidence into zero.

Additive measures (`events`, `edges`, `affected_endpoints`, `bytes`, and `usd`) use a declared
`sum`; rate and gauge measures use a declared `mean`. Each row reports its aggregation. Flow,
changes, topology, endpoints, and TLS support exact historical-window comparison. Path, cost,
and SLO currently expose latest/current state through Explorer, so the schema omits them from
`comparison_sources` and the comparison endpoint rejects them rather than pretending a current
snapshot is historical data.

Both input windows and the aligned output stay under the query's bounded row limit (at most
500). `current_truncated`, `previous_truncated`, and `rows_truncated` make a partial result
explicit. Narrow both windows or add a filter before interpreting a partial delta.

## Logical execution receipt

Every query response includes `execution` with contract
`explorer-execution/v1`. It is a server-authored “nutrition label” for the work
that just completed:

- allow-listed recipe and logical source;
- `tenant_scoped: true`, asserted only after the authenticated tenant is
  resolved and supplied to the source;
- normalized `from`, `to`, and `row_limit` bounds;
- selected dimensions, groupings, measures, and filter **keys**;
- rows produced by the tenant-scoped source, rows returned, and a bounded
  truncation reason;
- source, response-shaping, and total elapsed milliseconds.

Comparison responses include `explorer-comparison-execution/v1`: the current
and previous receipts plus the bounded alignment row count, truncation reason,
and timing. The native Explorer page exposes these facts in a keyboard-operable
details panel for normal, empty, partial, and one-sided results. The generic CLI
prints the same versioned JSON receipt.

The receipt never contains tenant identity, literal filter values, SQL,
physical database plans, index names, secrets, or datastore-wide cardinality.
ELI5: it shows the rules and the size of the authenticated tenant drawer that
was just opened; it does not reveal the drawer label or the warehouse floor
plan.

## Tenant and authorization boundary

There is no `tenant_id` field in `ExplorerQuery`. The server resolves the tenant from the
authenticated principal first, checks `ai.query`, then checks the selected source's existing
read permission. The store call receives that authoritative tenant. Semantic tenant filter
variants such as `tenant`, `tenant_id`, `tenant-id`, and `tenant.name` are rejected.

Value suggestions are calculated from the already-authorized result rows. There is no global
suggestion index to leak another tenant's site, endpoint, service, or certificate names.
Cross-tenant tests insert distinguishable flow rows in both comparison windows and prove that
the exact table, aligned values, suggestion list, and receipt-derived row counts stay inside
the caller's store partition. Receipt construction occurs only after that tenant-scoped source
call succeeds.

Saved Explorer views reuse `/v1/inventory/views`. That store's outer key is `tenant_id` and its
next key is the authenticated owner. A saved view contains grammar/filter choices only;
opening it reruns the current tenant's telemetry query. A copied foreign view ID is
indistinguishable from a missing ID (`404 saved view not found`).

## Context and evidence

The stable view link contains the recipe, absolute UTC time range, exact filters, and—when
enabled—the explicit previous UTC window. It never contains tenant identity or credentials.
Running a query pushes that stable view into browser history. Opening the link, including by
returning from native evidence with browser Back, re-executes the same read-only query inside
the newly authenticated tenant boundary so the result receipt is current rather than cached
client state. “Open evidence” uses the common short-lived pivot contract to carry the same
time/filter context to the source screen, and “Explain this view” uses the tenant/RBAC-scoped
AI evidence engine. The exact result table remains available beside both paths so a chart or
explanation never hides the source values.

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
probectl explorer compare --body '{
  "query":{
    "question":"Show service dependencies",
    "source":"topology",
    "from":"2026-07-14T11:00:00Z",
    "to":"2026-07-14T12:00:00Z",
    "dimensions":["from","to","kind"],
    "groupings":["kind"],
    "measures":["edges"],
    "visualization":"topology",
    "limit":100
  },
  "previous_from":"2026-07-14T10:00:00Z",
  "previous_to":"2026-07-14T11:00:00Z"
}'
```

The CLI and web client both use the versioned API. Authentication supplies tenant scope; do not
put a tenant selector in the body or URL.
