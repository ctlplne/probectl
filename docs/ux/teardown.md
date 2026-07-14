# Competitive UX teardown

Research snapshot: **2026-07-14**. This is the X0 baseline for the six journeys in
[`harness/UX_SEED.md`](../../../harness/UX_SEED.md). It evaluates the product UI a user can
operate, not the amount of backend code behind it.

## Method and limits

The competitor pass uses current first-party documentation, released screenshots, and
first-party workflow videos. We did not have licensed, equivalently populated competitor
tenants, so their action/time values are conservative **documented-flow estimates**, not
stopwatch benchmarks. A documented action is counted when the user changes a field, follows
a link, opens a control, or submits work. Hidden setup, waiting for telemetry, and optional
configuration are stated instead of being silently scored as zero.

The probectl baseline is stronger evidence: the counts come from current routes and scripted
component journeys, especially
[`onboarding.test.tsx`](../../web/src/test/onboarding.test.tsx),
[`incidents.test.tsx`](../../web/src/test/incidents.test.tsx),
[`path-viz.test.tsx`](../../web/src/test/path-viz.test.tsx),
[`topology.test.tsx`](../../web/src/test/topology.test.tsx), and
[`provider-console.test.tsx`](../../web/src/test/provider-console.test.tsx). Time is still a
proxy because the tests stub server and network latency. Secrets are excluded from keystroke
counts.

### Score anchors

Scores are integers from 1 (missing) to 5 (category-leading). Each D-column uses the same
anchor in all six journey tables.

| Dimension | 5 | 3 | 1 |
|---|---|---|---|
| D1 — time to first insight | real finding in <=15 minutes from a fresh supported install | <=60 minutes with guided setup | no complete fresh-install path |
| D2 — interactions to outcome | RCA and share in <=5 interactions | 10–14 or one context break | outcome cannot be completed |
| D3 — query expressiveness | 9–10 of the canonical questions answerable without docs | 5–6 | 0–1 |
| D4 — path/topology power | ECMP + hop metrics + what-if + history in one coherent flow | two of four | none |
| D5 — cross-plane pivots | four or more planes, one-hop pivots, time/filter preserved | two planes or partial context | no pivot |
| D6 — AI trust | inline explanation, exact claim-to-evidence links, and sovereign execution state | explanation/follow-up without exact evidence links | absent |
| D7 — onboarding/empty states | every shipped engine has readiness, next action, and progress | generic guidance for most surfaces | blank/error masquerades as healthy |
| D8 — alert round trip | fire, acknowledge, silence, maintenance, on-call/ticket, and postmortem link | three or four stages | rules/notifications only |
| D9 — density with clarity | passes all five heuristics below | passes three | decoration or ambiguity hides state |
| D10 — keyboard/a11y/perf | complete keyboard journey + axe + LCP/INP + bundle budgets | two of those controls | no published/observable control |

D9's five heuristics are: (1) scope and time are visible, (2) hierarchy makes the next action
obvious, (3) overview and exact values coexist, (4) detail is disclosed on demand, and (5)
decoration never competes with state. Intermediate scores interpolate between the anchors.
For D1 and D2 outside J1/J2, the score means setup burden and interactions to that journey's
outcome. A total is a diagnostic sum out of 50, not a claim that every dimension has equal
commercial value.

## Six replayable scripts

| ID | Start | Required end state | Counted proof |
|---|---|---|---|
| J1 install -> insight | supported self-host install with no telemetry | one real, named signal is visible and its producer is healthy | wall time, actions, commands, and every out-of-product handoff |
| J2 incident -> RCA -> share | a firing multi-plane incident | likely cause, exact evidence, and a stable tenant-authorized share/export | actions, context breaks, evidence hops, stable link/export |
| J3 explore -> answer | authenticated tenant home | answer ten canonical questions without documentation | questions answered, actions, syntax lookup, preserved filters |
| J4 path debug | a lossy ECMP path | bad hop/branch isolated, change over time compared, incident context and share retained | actions, visible ECMP/hop/MPLS data, scrub/compare/share |
| J5 fleet health | one stale and one version-skewed agent | unhealthy agents identified and the safe next action is obvious | actions, tenant scope, version/last-seen/readiness evidence |
| J6 MSP operations | provider operator sign-in | fleet triaged, a siloed tenant provisioned, usage exported under the probectl banner | actions, tenant isolation cues, privilege-domain separation, export |

J3's canonical questions are: top talkers by site; the ASN change preceding an incident; loss
by hop for a test; service dependencies; a saturated device interface; endpoints affected by
an outage; certificates expiring in 30 days; cross-AZ cost; SLO budget burn; and deployments
immediately preceding an incident.

## Fresh official-product evidence

### Kentik

Kentik Data Explorer remains the reference for dense flow exploration: its query sidebar
controls sources, time, dimensions, filters, visualizations, and saved views, with cause
analysis reachable from the result. AI Advisor can run as a page or overlay, exposes its plan
and tool progress, links details back to Data Explorer/KB, and supports reusable runbooks.
Kentik Map unifies cloud, Internet, and on-prem blocks with time, filters, health, historical
comparison, and details-on-demand. Sources:
[Data Explorer](https://kb.kentik.com/docs/data-explorer),
[AI Advisor](https://kb.kentik.com/v1/docs/ai-advisor),
[Kentik Map](https://kb.kentik.com/docs/kentik-map), and
[May 2026 AI updates](https://kb.kentik.com/docs/may-2026-ai-insights).

### Cisco ThousandEyes

Path Visualization exposes every selected agent-to-target path and grouping by agent,
network, location, interface, device, or network. Views Explanations is a two-action inline
flow—select a round, then Explain Selection—with follow-up prompts; adjacent rounds can be
compared. Traffic Insights pivots from a Path Visualization node into flow context. Internet
Insights adds map/table/topology outage context and a macro-to-micro pivot back to affected
tests. Sources: [Path Visualization](https://docs.thousandeyes.com/product-documentation/internet-and-wan-monitoring/path-visualization),
[Views Explanations](https://www.thousandeyes.com/blog/thousandeyes-views-explanations),
[Traffic Insights](https://docs.thousandeyes.com/product-documentation/traffic-insights/traffic-insights-views-and-settings),
and [Internet Insights workflow](https://docs.thousandeyes.com/product-documentation/getting-started/getting-started-with-internet-insights).

### Datadog Network Performance Monitoring

Network Analytics combines recommended queries, facets, group-by, summary graphs, a detailed
connection table, saved permalinks, and a side panel that pivots a network dependency into
flows, logs, traces, processes, integrations, and security findings. Network Path adds list,
path, health-over-time, per-hop detail, and side-by-side path comparison. The Network Map
automatically visualizes agent data and supports clustering and alert context. Sources:
[Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/),
[Network Map](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_map/),
[Path view](https://docs.datadoghq.com/network_monitoring/network_path/path_view/), and
[NetFlow Monitoring](https://docs.datadoghq.com/network_monitoring/netflow/).

### Grafana

Grafana remains the composability and operator-density reference. Drilldown provides
queryless Search -> Filter -> Visualize -> Investigate -> Add-to-dashboard exploration;
classic Explore supports split comparison and synchronized time. Dashboards have a real
keyboard vocabulary and broad link/snapshot/PDF/JSON/report sharing. The former Drilldown
Investigations product was removed in January 2026, so this review does not award it points.
Sources: [Drilldown workflow](https://grafana.com/docs/learning-hub/explore-your-data/01-metrics-drilldown/10-exploration-workflow/),
[Explore](https://grafana.com/docs/grafana/latest/visualizations/explore/get-started-with-explore/),
[dashboard shortcuts](https://grafana.com/docs/grafana/latest/visualizations/dashboards/use-dashboards/),
[sharing](https://grafana.com/docs/grafana/latest/dashboards/share-dashboards-panels/), and
[Investigations removal](https://grafana.com/blog/removal-of-drilldown-investigations-in-grafana-what-you-need-to-know/).

### Auvik

Auvik is the onboarding/fleet benchmark. Its collector discovery usually begins mapping in
5–15 minutes; the map automatically builds from protocols such as SNMP, LLDP, and CDP and
makes inferred links explicit. The multi-site map aggregates site health and alert severity,
while alert operations inherit across MSP/site scopes. Dashboards are fixed rather than
custom, but they are immediately legible. Sources:
[getting started](https://support.auvik.com/hc/en-us/articles/201440044-Getting-started-guide),
[topology discovery](https://support.auvik.com/hc/en-us/articles/202956414-How-does-Auvik-discover-network-topology-and-device-information),
[network map](https://support.auvik.com/hc/en-us/articles/204908674-Your-network-map),
[navigation](https://support.auvik.com/hc/en-us/articles/205199090-Navigating-Auvik), and
[dashboards](https://support.auvik.com/hc/en-us/articles/206618126-What-dashboards-are-available).

## Documented-flow action/time estimates

Notation is `actions / active-time proxy`; `+` means a lower bound because installation,
telemetry wait, or account configuration remains. These estimates make the scoring
falsifiable; a licensed replay should replace them in `rubric-results.md`.

| Product | J1 | J2 | J3 | J4 | J5 | J6 |
|---|---:|---:|---:|---:|---:|---:|
| Kentik | 9+ / 30–60m | 6–9 / 3–7m | 3–6 / 2–5m | 5–8 / 3–7m | 4–7 / 2–5m | 8+ / 5–10m |
| ThousandEyes | 10+ / 30–60m | 4–7 / 2–5m | 6–10 / 4–8m | 3–6 / 2–5m | 4–8 / 3–6m | 8+ / 5–10m |
| Datadog NPM | 6–10 / 15–30m | 5–8 / 3–6m | 3–6 / 2–5m | 4–7 / 3–6m | 4–7 / 2–5m | 8+ / 5–10m |
| Grafana | 10+ / 30–60m | 5–9 / 4–8m | 3–7 / 3–8m | 8+ / 8–15m | 4–7 / 3–6m | 8+ / 5–10m |
| Auvik | 5–8 / 5–15m | 6–10 / 5–10m | 6–10 / 5–10m | 3–6 / 2–5m | 2–5 / 1–3m | 4–7 / 2–5m |

## Per-journey D1–D10 scores

### J1 — fresh install to first real insight

| Product | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | /50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Kentik | 3 | 3 | 5 | 4 | 4 | 4 | 4 | 5 | 4 | 3 | 39 |
| ThousandEyes | 3 | 3 | 3 | 5 | 4 | 4 | 4 | 4 | 4 | 3 | 37 |
| Datadog NPM | 4 | 4 | 4 | 4 | 5 | 3 | 4 | 5 | 5 | 4 | 42 |
| Grafana | 2 | 2 | 5 | 2 | 4 | 2 | 2 | 4 | 5 | 5 | 33 |
| Auvik | 5 | 4 | 2 | 4 | 2 | 1 | 5 | 4 | 4 | 3 | 34 |
| **probectl today** | **2** | **2** | **2** | **3** | **3** | **4** | **3** | **3** | **3** | **3** | **28** |

The category max is Auvik's 5–15 minute discovery loop. probectl's first-run page is guided
and tenant-safe, but it hands the user a shell enrollment command and marks token creation as
agent progress before a producer is actually healthy or a finding exists.

### J2 — incident to cited RCA to share

| Product | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | /50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Kentik | 4 | 4 | 4 | 4 | 4 | 4 | 4 | 5 | 4 | 3 | 40 |
| ThousandEyes | 4 | 4 | 3 | 5 | 5 | 4 | 4 | 4 | 4 | 3 | 40 |
| Datadog NPM | 4 | 4 | 4 | 4 | 5 | 3 | 4 | 5 | 5 | 4 | 42 |
| Grafana | 3 | 3 | 5 | 2 | 4 | 2 | 3 | 5 | 5 | 5 | 37 |
| Auvik | 4 | 3 | 2 | 3 | 2 | 1 | 4 | 4 | 4 | 3 | 30 |
| **probectl today** | **3** | **1** | **2** | **3** | **4** | **4** | **3** | **4** | **3** | **3** | **30** |

probectl has the hardest trust primitive here: citations jump to exact evidence and
uncited root-cause claims are suppressed. The journey still fails D2 because Incidents -> Ask
is a route change and there is no incident snapshot/permalink/export action after the answer.

### J3 — explore to answer ten canonical questions

| Product | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | /50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Kentik | 4 | 4 | 5 | 4 | 4 | 4 | 4 | 4 | 5 | 3 | 41 |
| ThousandEyes | 4 | 4 | 3 | 5 | 4 | 4 | 4 | 4 | 4 | 3 | 39 |
| Datadog NPM | 4 | 4 | 5 | 4 | 5 | 3 | 4 | 5 | 5 | 4 | 43 |
| Grafana | 3 | 3 | 5 | 2 | 4 | 2 | 3 | 5 | 5 | 5 | 37 |
| Auvik | 4 | 3 | 2 | 3 | 2 | 1 | 4 | 4 | 4 | 3 | 30 |
| **probectl today** | **3** | **3** | **2** | **3** | **3** | **4** | **3** | **3** | **3** | **3** | **30** |

Kentik, Datadog, and Grafana offer a discoverable structured exploration grammar. probectl
has strong individual plane pages and a natural-language Ask surface, but no Data
Explorer-class surface that teaches dimensions, previews the query, and retains a result as
a shareable view.

### J4 — debug a lossy ECMP path

| Product | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | /50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Kentik | 3 | 4 | 4 | 4 | 4 | 4 | 4 | 5 | 4 | 3 | 39 |
| ThousandEyes | 4 | 5 | 3 | 5 | 5 | 4 | 4 | 4 | 5 | 3 | 42 |
| Datadog NPM | 4 | 4 | 4 | 5 | 5 | 3 | 4 | 5 | 5 | 4 | 43 |
| Grafana | 2 | 3 | 5 | 2 | 3 | 2 | 2 | 4 | 4 | 5 | 32 |
| Auvik | 5 | 4 | 2 | 4 | 2 | 1 | 5 | 4 | 4 | 3 | 34 |
| **probectl today** | **3** | **3** | **2** | **3** | **3** | **2** | **3** | **3** | **3** | **3** | **28** |

probectl already renders merged ECMP branches, per-hop loss/latency, MPLS detail, and an
accessible table. History and what-if exist on the separate Topology page, but the path does
not preserve its test/time context into that page and has no compare, incident overlay,
explain-this-view, or share control.

### J5 — find and act on fleet health

| Product | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | /50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Kentik | 3 | 4 | 4 | 4 | 4 | 4 | 4 | 5 | 4 | 3 | 39 |
| ThousandEyes | 4 | 4 | 3 | 4 | 4 | 4 | 5 | 4 | 4 | 3 | 39 |
| Datadog NPM | 4 | 4 | 4 | 4 | 5 | 3 | 4 | 5 | 5 | 4 | 42 |
| Grafana | 2 | 3 | 5 | 2 | 4 | 2 | 2 | 5 | 5 | 5 | 35 |
| Auvik | 5 | 5 | 3 | 5 | 4 | 1 | 5 | 5 | 5 | 3 | 41 |
| **probectl today** | **4** | **4** | **2** | **3** | **3** | **2** | **4** | **3** | **3** | **3** | **31** |

The tenant Admin page shows status, version, capabilities, filtering, enrollment, and
collector registration. The MSP surface aggregates online/stale/version counts. Neither is
yet an action center: last-seen reason, rollout state, recommended safe action, and a direct
tenant-to-agent pivot are missing.

### J6 — MSP multi-tenant operations under the probectl banner

| Product | D1 | D2 | D3 | D4 | D5 | D6 | D7 | D8 | D9 | D10 | /50 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Kentik | 3 | 3 | 4 | 4 | 4 | 4 | 4 | 5 | 4 | 3 | 38 |
| ThousandEyes | 3 | 3 | 3 | 4 | 4 | 4 | 4 | 4 | 4 | 3 | 36 |
| Datadog NPM | 3 | 3 | 4 | 4 | 5 | 3 | 3 | 5 | 5 | 4 | 39 |
| Grafana | 2 | 3 | 5 | 2 | 4 | 2 | 2 | 5 | 5 | 5 | 35 |
| Auvik | 5 | 5 | 3 | 5 | 4 | 1 | 5 | 5 | 5 | 3 | 41 |
| **probectl today** | **4** | **4** | **2** | **3** | **3** | **2** | **4** | **3** | **3** | **2** | **30** |

probectl's provider console is correctly outside the tenant shell, says that operators have
no implicit telemetry access, and puts inventory, isolation/residency, fleet, usage export,
fairness, governance, and break-glass on one surface. The present page is a long stack of
independent cards, lacks task navigation and keyboard commands, and still contains a branding
card scheduled for removal by W11; therefore it is not yet the crisp MSP demo moment.

## probectl-today interaction baseline

These are the numbers X-lane journey tests must beat. “Incomplete” is deliberately not turned
into a flattering time.

| Journey | Current shortest source-backed path | UI/command interactions | Keystrokes | Active-time proxy | Completion gap |
|---|---|---:|---:|---:|---|
| J1 | default onboarding -> mint -> copy/run agent command -> replace example target -> create test -> navigate to results | 8 | ~34 + shell command | 15–30m | no health wait or first-finding receipt; token minted can look complete |
| J2 | auto-selected incident -> Ask about incident -> submit prefilled question -> open exact citation | 4 | 0 | 1–3m to RCA | **incomplete:** no stable share/export |
| J3 | Ask textarea + submit, repeated for ten questions; manual plane pages for unsupported answers | >=20 | ~480 | 10–20m | only about 3/10 are discoverable through one query surface without docs |
| J4 | select/run path -> inspect hop -> manually open Topology -> select/simulate -> type historical time | 5–7 | 16 | 2–4m | compare, incident overlay, context-preserving pivot, and share absent |
| J5 | command palette -> Admin -> filter stale/offline agents | 3 | 7 | <=1m | row has status/version but no reason, rollout state, or next action |
| J6 | provider MFA sign-in -> scan fleet -> choose siloed -> enter residency/slug/name -> provision -> export usage | 10 | ~32 + credentials | 2–4m | page-stack scanning, no task nav/palette, no guided fleet action |

Counting rules: opening the command palette plus executing a command is one compound keyboard
interaction in the table; each committed field/select and each submit/copy/navigation is one;
reading and scrolling are not counted. J1 uses the product defaults except that the
`app.example.test` placeholder must be replaced before the result can be called real.

## Gap decomposition decisions

The rubric supports every original seed, but several seeds are too coupled to remain one
task. X0 therefore replaces the 12 placeholders with 18 atomic tasks:

- incident room layout, citation/explain trust, and sharing become separate tasks so each has
  a measurable journey target;
- path rendering and path history/compare become separate tasks;
- the shared time/filter/selection context contract becomes its own prerequisite instead of
  being reimplemented per page;
- design tokens and product-wide demo/empty-state honesty remain independent gates;
- fleet health and MSP operations become distinct because they run in separate privilege
  domains;
- journey measurement is first, so later “fewer clicks” claims cannot be hand-counted; and
- accessibility/performance and keyboard coverage remain separate because a mouse-free path
  does not prove LCP, INP, bundle size, or rendered WCAG behavior.

The target remains binding: the final
[`docs/ux/rubric-results.md`](./rubric-results.md) must show probectl at or above the
competitor maximum on at least four journeys and at or above the competitor median on all six.
