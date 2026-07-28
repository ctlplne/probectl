# probectl UX design principles

These are executable product rules, not mood-board adjectives. They turn the competitive
baseline in [`teardown.md`](./teardown.md) into review and CI criteria while preserving the
security contract in [`CLAUDE.md`](../../CLAUDE.md).

## 1. Evidence before eloquence

An AI sentence is useful only when the operator can inspect why it exists. Every causal claim
must link to the exact tenant-authorized evidence object; clicking it must preserve the
incident, time range, filters, and selection. If evidence is missing or outside authorization,
the UI says “insufficient evidence” and omits the claim. Confidence is never a substitute for
provenance.

Why: probectl's RCA engine already drops findings whose citations do not resolve, while
ThousandEyes Views Explanations and Kentik AI Advisor set the interaction expectation for
inline reasoning ([ThousandEyes](https://www.thousandeyes.com/blog/thousandeyes-views-explanations),
[Kentik](https://kb.kentik.com/v1/docs/ai-advisor)).

Test: an answer fixture containing one valid and one invalid citation renders only the valid
claim; activating its evidence link focuses the matching row; tenant A can never resolve a
tenant B evidence ID.

Implementation receipt: Incidents, Path, Topology, and all Plane tabs expose one reusable
`Explain this view` action. It carries the X3 time/filter/entity context into `/v1/ai/ask`,
keeps the explanation in the current inspector, and re-checks every citation against the
authorized evidence array before rendering causal prose.

## 2. One incident, five planes, one clock

Network, routing, flow, device, and eBPF signals are lenses on one event—not five products.
Every incident surface uses one visible time range and one tenant scope. A plane pivot must be
one interaction and carry `tenant (server-derived) + incident + from/to + filters + selection`.
The destination may narrow the context but may not silently reset it.

Why: Datadog's flow-to-logs/traces/processes side panel and ThousandEyes' synthetic-to-flow
pivot demonstrate the speed of contextual pivots, but probectl's correlation gate covers five
planes ([Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/),
[ThousandEyes Traffic Insights](https://docs.thousandeyes.com/product-documentation/traffic-insights)).

Test: each registered plane pivot is exercised from a fixed incident fixture; one activation
lands on the right evidence with identical time/filter parameters and no client-supplied
`tenant_id`.

## 3. Sovereignty is observable state

AI surfaces display where reasoning ran: `Built-in · local/air-gapped`, or the named external
adapter with its recorded egress-consent state. “Sovereign” is never a decorative badge. It
must be computed from server-reported adapter state, have a plain-language explanation, and
remain useful without third-party fonts, scripts, analytics, or model calls.

Test: built-in mode renders an accessible local/air-gapped badge and makes zero model-egress
requests; an external adapter without consent fails closed and explains the next authorized
step.

Implementation receipt: `AIAnswer.reasoning` is server-authored structured state; the browser
does not parse `model` or configuration text. Denied remote RCA attempts are recorded as
`ai.remote_egress_denied` before the external adapter can be called.

## 4. The tenant boundary is visible and structural

The current tenant indicator never disappears in the tenant application. Tenant scope is
resolved at the server/storage boundary, not accepted from an editable browser field. The
provider console stays a visually separate privilege domain and says plainly that provider
operators have no implicit telemetry access. Break-glass is explicit, time-bound,
tenant-consented, and separately audited.

Test: rendered-route coverage asserts the tenant indicator on every tenant-native route and
its absence from `/provider`; cross-tenant tests prove that copied URLs and evidence IDs fail
closed in the wrong tenant.

## 5. Keyboard is a first-class API

Every journey has a stable command vocabulary, not merely tab-order survival. The command
palette can start the journey; focus is visible; dialogs trap and restore focus; graph actions
have equivalent list/table actions; Escape is safe; no essential state exists only on hover.
Labels describe the operator outcome (“Compare paths”), not the implementation (“Open modal”).

Why: Grafana documents a broad shortcut vocabulary, and probectl already has an ARIA combobox
palette and keyboard-operable path/topology nodes
([Grafana shortcuts](https://grafana.com/docs/grafana/latest/visualizations/dashboards/use-dashboards/)).

Test: scripted keyboard-only tests complete J1–J6 with zero pointer events and assert the
documented interaction budgets.

Implementation receipt: the generated
[`keyboard-command-reference.md`](./keyboard-command-reference.md) comes from the same typed
registry as the palette. Cross-plane commands serialize only the X3 allow-list; disabled
commands state why; palette and modal focus trap/restore; and a tenant switch clears the
object/action-bearing URL before credentials can change.

## 6. Dense, then disclose

An expert should see scope, time, health, magnitude, change, and the next action without
scrolling through decoration. Tables keep exact values; visualizations reveal shape; the same
selection coordinates both. Secondary evidence opens in an inspector/drawer, and raw data is
available without becoming the default view. Color is redundant with text/icon/shape.

Why: Kentik Data Explorer and Map, Datadog Network Analytics, and Auvik's map all pair overview
with exact drill-down ([Kentik Data Explorer](https://kb.kentik.com/docs/data-explorer),
[Datadog](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/),
[Auvik map](https://support.auvik.com/hc/en-us/articles/204908674-Your-network-map)).

Test: the 1440×900 reference screenshot exposes the journey's scope/time/key health/next
action above the fold; the accessible table and visualization report the same fixture values;
axe reports no serious/critical violations in both themes.

On mobile, a selected tab leads directly to its workspace; overview cards follow the selected
evidence instead of pushing it below redundant summaries.

## 7. Empty means truthful state—never “zero-ish”

Every tenant-data empty state names one of six server-derived truths: ready but no data,
blocked by configuration, permission denied, degraded, genuinely quiet, or isolated demo.
It shows producer readiness, last successful ingest when available, the coverage limitation,
and one authorized next action. Demo/sample data is globally and persistently badged and
exits with Shift+D; sample pixels never mix with live tenant data.

Test: fixture coverage exercises all six states and audits every native data route's truth
sources; no `running:false`, unavailable-store, or failed-fetch fixture renders a healthy zero,
sample pixel, or generic “no data.” See [the X18 contract and demo runbook](demo-mode.md).

## 8. Hero views answer an operational question

Path answers “where did this flow degrade, what changed, and who is affected?” Topology
answers “what depends on this, and what happens if it fails?” Incidents answer “what is the
most likely cause, which evidence proves it, and what safe human-gated step comes next?” A
hero view is finished only when its answer can be compared over time and shared without
losing tenant authorization or context.

Test: J2 and J4 fixtures have explicit answer assertions, not screenshot-only assertions;
share links replay identical time/filter/selection state for an authorized user and return
nothing for another tenant.

## 9. Human gates are product state, not fine print

Detection never looks like prevention, and a proposal never looks executed. Remediation
surfaces show `observe-only`, dry-run output, blast radius, approvals, actor, and audit receipt
before any allowed action. Disabled actions explain which authority is missing. The UI never
uses urgency or animation to pressure approval.

Test: proposal fixtures cannot expose an execution control when approvals are disabled; every
state transition has an immutable audit reference; threat detections use signal/confidence
language rather than blocked/prevented language.

## 10. Performance and accessibility are correctness

The design-token system owns color, spacing, type, radius, density, visualization palette,
and motion. Motion respects `prefers-reduced-motion` and never carries unique meaning. Every
native route meets WCAG 2.2 AA and explicit LCP, INP, and route/bundle budgets on the reference
profile. A feature that breaks a budget is incomplete, even if its API is correct.

Test: CI runs unit axe, rendered-browser axe in every theme, keyboard journeys, LCP/INP
budgets, and route/chunk size checks. There are no hardcoded design values, third-party fonts,
or default outbound browser requests.

The CI reference profile is deliberately fixed and local: the production bundle,
deterministic same-origin API fixtures, pinned Chromium, dark and aurora themes,
1366×900 desktop plus 390×844 mobile accessibility viewports, and five fresh browser
contexts for every J1–J6 landing route. The performance checker recomputes nearest-rank
p75 from the five raw samples and enforces LCP <2.5 seconds and INP <200 milliseconds.
The bundle checker enforces initial JavaScript <=250 KiB gzip and every lazy route
entry <=150 KiB gzip. Both ceilings are enforcement-code constants, not generated
baselines. CI retains `receipts/web-ux/rendered-a11y.json`, `web-performance.json`,
and `bundle-budget.json`; a missing route, matrix cell, run, dynamic route entry, or
receipt is a red build.

Implementation receipt: X17 adds deployment-level comfortable/compact density tokens and
wires them into controls, rows, panels, and tables. Compact mode keeps a 44px coarse-pointer
target. Six chart colors are paired with dash-pattern tokens, observed/estimated/missing
states have non-color border styles, and graph selection combines color with a thicker
outline. Shared focus, selection, layer, duration, and easing tokens are contrast-tested in
both themes. `prefers-reduced-motion` zeros every duration while visible labels and shapes
continue to communicate state. The token gate scans core and commercial product CSS and
rejects raw color, spacing, type, radius, z-index, duration, or easing values. Overrides are
one deployment-wide allowlisted theme; selectors and tests reject tenant-addressed themes.

## Review shorthand

A UX change is ready when a reviewer can answer yes to all five questions:

1. Can I tell which tenant, time, and data state I am viewing?
2. Can I reach the exact evidence and see what is uncertain or unavailable?
3. Can I finish the relevant scripted journey within its measured interaction budget using
   only the keyboard?
4. Does the same flow fail closed across tenants and preserve human gates?
5. Do rendered a11y, performance, bundle, and token gates pass with real fixture data?
