# Final competitive UX rubric results

Measured: **2026-07-15** on the remediation HEAD. Competitor scores are the fixed
2026-07-14 first-party-documentation snapshot in
[`teardown.md`](./teardown.md); keeping those rows unchanged prevents the finish line from
moving after implementation. The probectl row is rescored against the same D1-D10 anchors
using the deterministic J1-J6 fixtures in `web/src/test/journeys/`, the versioned
[`journey-baseline.json`](./journey-baseline.json), and the rendered-browser accessibility,
performance, and bundle receipts.

“probectl today” is retained as the machine-readable row label expected by the rubric gate;
in this file it means the final remediation HEAD, not the pre-X-lane baseline.

## Binding result

| Journey | Competitor median | Competitor maximum | probectl final | At/above median | At/above maximum |
| ------- | ----------------: | -----------------: | -------------: | :-------------: | :--------------: |
| J1      |                37 |                 42 |             49 |       yes       |       yes        |
| J2      |                40 |                 42 |             50 |       yes       |       yes        |
| J3      |                39 |                 43 |             50 |       yes       |       yes        |
| J4      |                39 |                 43 |             50 |       yes       |       yes        |
| J5      |                39 |                 42 |             47 |       yes       |       yes        |
| J6      |                38 |                 41 |             44 |       yes       |       yes        |

The binding target is met: probectl is at or above the competitor median on **6/6** journeys
and at or above the competitor maximum on **6/6** journeys (the requirement is at least
4/6). These are source-backed interaction proxies, not claims about competitor server or
network latency.

## Final replay measurements

| Journey | Complete outcome                                          | Interactions | Typed characters |                Context breaks | Active-time proxy |
| ------- | --------------------------------------------------------- | -----------: | ---------------: | ----------------------------: | ----------------: |
| J1      | healthy producer plus named real finding                  |            8 |     0 in product | 1 documented shell enrollment |          6–12 min |
| J2      | cited RCA plus authorized stable replay                   |            4 |                0 |                             0 |         15–45 sec |
| J3      | 10/10 canonical questions answered                        | 2 per answer |                0 |                             0 |     1–3 min total |
| J4      | lossy ECMP branch isolated, compared, shared, and pivoted |            5 |                0 |                             0 |         30–90 sec |
| J5      | stale/skewed agents identified and safe action opened     |            2 |                0 |                             0 |          5–30 sec |
| J6      | metadata triage, siloed EU tenant, and usage export       |  8 after MFA |               16 |                             0 |        30–120 sec |

J1's shell handoff is explicit rather than hidden: the product supplies one tenant-bound
command, then refuses to call onboarding complete until the server reports a healthy producer
and a real result. Every journey has a keyboard-equivalent path with no larger interaction
budget. Copied URLs use opaque artifact/round identifiers and never accept client-authored
tenant scope.

## Per-journey D1-D10 scores

### J1 — fresh install to first real insight

| Product        | D1  | D2  | D3  | D4  | D5  | D6  | D7  | D8  | D9  | D10 | /50 |
| -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Kentik         | 3   | 3   | 5   | 4   | 4   | 4   | 4   | 5   | 4   | 3   | 39  |
| ThousandEyes   | 3   | 3   | 3   | 5   | 4   | 4   | 4   | 4   | 4   | 3   | 37  |
| Datadog NPM    | 4   | 4   | 4   | 4   | 5   | 3   | 4   | 5   | 5   | 4   | 42  |
| Grafana        | 2   | 2   | 5   | 2   | 4   | 2   | 2   | 4   | 5   | 5   | 33  |
| Auvik          | 5   | 4   | 2   | 4   | 2   | 1   | 5   | 4   | 4   | 3   | 34  |
| probectl today | 5   | 4   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 49  |

Receipt: J1 separates token creation, connection, producer health, and first finding; the
6–12 minute proxy is below the 15-minute D1 anchor. The one shell command keeps D2 at 4
instead of claiming a fully in-browser install.

### J2 — incident to cited RCA to share

| Product        | D1  | D2  | D3  | D4  | D5  | D6  | D7  | D8  | D9  | D10 | /50 |
| -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Kentik         | 4   | 4   | 4   | 4   | 4   | 4   | 4   | 5   | 4   | 3   | 40  |
| ThousandEyes   | 4   | 4   | 3   | 5   | 5   | 4   | 4   | 4   | 4   | 3   | 40  |
| Datadog NPM    | 4   | 4   | 4   | 4   | 5   | 3   | 4   | 5   | 5   | 4   | 42  |
| Grafana        | 3   | 3   | 5   | 2   | 4   | 2   | 3   | 5   | 5   | 5   | 37  |
| Auvik          | 4   | 3   | 2   | 3   | 2   | 1   | 4   | 4   | 4   | 3   | 30  |
| probectl today | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 50  |

Receipt: one incident room preserves the server-derived tenant, UTC clock, filters, selected
evidence, and five-plane pivots. Causal prose is suppressed unless its exact authorized
citation resolves; a four-action keyboard flow produces a random-ID replay artifact with the
same citations and reasoning provenance.

### J3 — explore to answer ten canonical questions

| Product        | D1  | D2  | D3  | D4  | D5  | D6  | D7  | D8  | D9  | D10 | /50 |
| -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Kentik         | 4   | 4   | 5   | 4   | 4   | 4   | 4   | 4   | 5   | 3   | 41  |
| ThousandEyes   | 4   | 4   | 3   | 5   | 4   | 4   | 4   | 4   | 4   | 3   | 39  |
| Datadog NPM    | 4   | 4   | 5   | 4   | 5   | 3   | 4   | 5   | 5   | 4   | 43  |
| Grafana        | 3   | 3   | 5   | 2   | 4   | 2   | 3   | 5   | 5   | 5   | 37  |
| Auvik          | 4   | 3   | 2   | 3   | 2   | 1   | 4   | 4   | 4   | 3   | 30  |
| probectl today | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 50  |

Receipt: Explorer teaches and executes all ten canonical questions with two interactions per
answer, zero query typing, no syntax lookup, one shared clock/filter model, exact table/chart
agreement, saved views, and cited explain-this-view output.

### J4 — debug a lossy ECMP path

| Product        | D1  | D2  | D3  | D4  | D5  | D6  | D7  | D8  | D9  | D10 | /50 |
| -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Kentik         | 3   | 4   | 4   | 4   | 4   | 4   | 4   | 5   | 4   | 3   | 39  |
| ThousandEyes   | 4   | 5   | 3   | 5   | 5   | 4   | 4   | 4   | 5   | 3   | 42  |
| Datadog NPM    | 4   | 4   | 4   | 5   | 5   | 3   | 4   | 5   | 5   | 4   | 43  |
| Grafana        | 2   | 3   | 5   | 2   | 3   | 2   | 2   | 4   | 4   | 5   | 32  |
| Auvik          | 5   | 4   | 2   | 4   | 2   | 1   | 5   | 4   | 4   | 3   | 34  |
| probectl today | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 5   | 50  |

Receipt: the above-fold view combines merged ECMP branches, hop metrics/MPLS, exact searchable
rows, round history and diff, incident/change overlays, cited explanation, and a stable share.
Five interactions isolate, compare, share, and pivot while retaining the selected branch and
clock; color is redundant with text, stroke pattern, and shape.

### J5 — find and act on fleet health

| Product        | D1  | D2  | D3  | D4  | D5  | D6  | D7  | D8  | D9  | D10 | /50 |
| -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Kentik         | 3   | 4   | 4   | 4   | 4   | 4   | 4   | 5   | 4   | 3   | 39  |
| ThousandEyes   | 4   | 4   | 3   | 4   | 4   | 4   | 5   | 4   | 4   | 3   | 39  |
| Datadog NPM    | 4   | 4   | 4   | 4   | 5   | 3   | 4   | 5   | 5   | 4   | 42  |
| Grafana        | 2   | 3   | 5   | 2   | 4   | 2   | 2   | 5   | 5   | 5   | 35  |
| Auvik          | 5   | 5   | 3   | 5   | 4   | 1   | 5   | 5   | 5   | 3   | 41  |
| probectl today | 5   | 5   | 4   | 4   | 5   | 4   | 5   | 5   | 5   | 5   | 47  |

Receipt: a two-action keyboard path identifies stale and version-skewed agents and opens
evidence-only guidance. Rows expose heartbeat reason, version compatibility, capabilities,
readiness, rollout cohort/state, and last failure. Guidance retains signed-artifact, staged
cohort, health-gate, rollback, tenant/RBAC, audit, and human-approval constraints; it cannot
push an update.

### J6 — MSP multi-tenant operations under the probectl banner

| Product        | D1  | D2  | D3  | D4  | D5  | D6  | D7  | D8  | D9  | D10 | /50 |
| -------------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Kentik         | 3   | 3   | 4   | 4   | 4   | 4   | 4   | 5   | 4   | 3   | 38  |
| ThousandEyes   | 3   | 3   | 3   | 4   | 4   | 4   | 4   | 4   | 4   | 3   | 36  |
| Datadog NPM    | 3   | 3   | 4   | 4   | 5   | 3   | 3   | 5   | 5   | 4   | 39  |
| Grafana        | 2   | 3   | 5   | 2   | 4   | 2   | 2   | 5   | 5   | 5   | 35  |
| Auvik          | 5   | 5   | 3   | 5   | 4   | 1   | 5   | 5   | 5   | 3   | 41  |
| probectl today | 5   | 4   | 4   | 4   | 5   | 2   | 5   | 5   | 5   | 5   | 44  |

Receipt: the visually separate provider plane ranks metadata-only fleet exceptions,
lifecycle/isolation/residency, usage, fairness, break-glass, governance, and operators. Eight
post-MFA keyboard interactions triage an exception, provision a siloed EU tenant, and open
usage export. The score deliberately keeps D6 at 2 because provider operations do not invent
an AI step; tenant telemetry remains inaccessible without tenant-consented, time-bounded,
separately audited break-glass. Product identity remains probectl for every tenant.

## Enforcement receipts

- `web/src/test/journeys/keyboard-only.test.tsx` replays J1-J6 with zero pointer events and
  asserts keyboard counts never exceed the measured pointer budgets.
- Journey-specific tests prove each required end state and reject client-authored tenant
  scope; incomplete outcomes cannot receive a flattering time.
- The rendered Chromium matrix covers every native route in dark/aurora at desktop/mobile,
  checks axe plus focus/target constraints, and records deterministic J1-J6 LCP/INP samples.
- Bundle, token, theme-contrast, honest-empty-state, surface-coverage, and no-outbound gates
  are executable CI checks rather than review-only claims.
