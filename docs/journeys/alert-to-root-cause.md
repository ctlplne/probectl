# From alert to root cause

You are on call. A page just woke you up. This journey walks you from that first
buzz to a closed incident with a *cited* cause — the kind you can paste into the
postmortem and defend. Think of it as the route from "the smoke alarm went off"
to "it was the toaster, here is the scorch mark."

## Who this is for

The on-call engineer holding the pager. You did not build the dashboards and you
do not have time to read five of them at 3 a.m. You want one screen that tells
you *what broke*, *why*, and *what changed just before* — with evidence you can
trust, all scoped to your own [tenant](../glossary.md) (one isolated customer or
organization; the outermost boundary every record is scoped by).

## Before you start

You need a running control plane with data already flowing — agents probing,
results landing, at least one observability plane reporting. If none of that is
true yet, start with the [getting started guide](../getting-started.md) and come
back once probes are running. This journey reads and acts on live signals; it
does not create the producers that generate them.

You also need an authentication token with read access to alerts, incidents, the
AI assistant, and topology. Every command below is a versioned REST call over
HTTPS to your own control plane, scoped to your tenant — an unknown tenant fails
closed and returns nothing.

## The path

1. **Set a service-level objective (SLO) and an alert rule.** Before the page can
   mean anything, decide what "broken" *is*. An SLO turns a promise like "checkout
   succeeds 99% of the time" into a number probectl watches continuously; the 1%
   you are allowed to fail is your *error budget*, a balance you spend as failures
   happen. Define the SLO as an OpenSLO file, point the loader at it, then read the
   tenant's SLO status to confirm it is tracked:

   ```sh
   # Confirm your SLO is loaded and tracked (attainment, error budget, burn rates).
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     https://control.example/v1/slos
   ```

   You observe attainment versus objective, error budget remaining, and per-window
   *burn rates* (how fast you are spending the budget). A brand-new SLO reports
   `cold_start: true` until it has seen 50 events — that is deliberate, so a single
   failure on thin data does not page you. Next, register an alert rule so a
   crossing actually reaches a human. Reading rules needs `alert.read`; creating
   one needs `alert.write`:

   ```sh
   # List your tenant's alert rules (the durable "what I configured" layer).
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     https://control.example/v1/alerts
   ```

   You observe your rules — each either a *threshold* rule (a value crosses a fixed
   line, like packet loss above 2%) or a *baseline* rule (a value drifts from its
   own learned normal). Powered by [cost, reliability, chaos and carbon
   intelligence](../features/cost-slo-and-chaos.md) (the SLO) and [alerting and
   incidents](../features/alerting-and-incidents.md) (the rule).

2. **Get paged, then open the correlated incident on the timeline.** The page
   fired. Resist the urge to chase the alert — first ask the engine what is firing
   *right now* for your tenant. "What is firing" is recomputed on every evaluation
   pass, so this is never a stale browser guess:

   ```sh
   # What is firing right now, your tenant only (needs alert.read).
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     https://control.example/v1/alerts/active
   ```

   You observe a list where each firing series carries an opaque `fingerprint` (its
   rule + label-set identity), a severity, and its operator state — plus an
   `evaluator_running: true|false` flag that honestly distinguishes "quiet, nothing
   firing" from "the evaluator is not running here." Now pull the *incident*, not
   the raw alerts. probectl folds related signals from every plane into one
   tenant-scoped incident — so a routing flip that trips a dozen detectors reads as
   one story, not twelve pages:

   ```sh
   # List correlated incidents, then drill into one for its cross-plane evidence.
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     https://control.example/v1/incidents
   ```

   You observe one incident object whose evidence list spans planes — for example a
   failing synthetic probe *and* the affected service edge — with related change and
   topology context attached, all scoped to your tenant. Powered by [alerting and
   incidents](../features/alerting-and-incidents.md).

3. **Ask the AI assistant for a grounded root-cause analysis (RCA) with cited
   evidence.** RCA is the work of figuring out *why* something broke — the part
   humans are worst at under pressure, because the symptoms scatter across metrics,
   routing, flow, and change records. Ask in plain English. The assistant enforces
   your tenant first, then your role, *before* any model runs, and every claim it
   returns links back to a real signal you are allowed to see:

   ```sh
   # Ask a grounded question (needs ai.query). The question cannot name a tenant.
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     -X POST https://control.example/v1/ai/ask \
     -H 'Content-Type: application/json' \
     -d '{"question":"why is checkout slow for the EU region?","subject":{"target":"checkout.eu.acme.example"}}'
   ```

   You observe a cited Answer: a probable root cause, a confidence level, and
   findings whose citation chips each resolve to an underlying signal. It is a
   fact-checking editor who walks every footnote back to its source — any finding
   whose citation does not resolve to real gathered evidence is dropped, and if
   nothing grounded survives you get an honest "insufficient evidence" rather than a
   guess. Powered by [the AI assistant](../features/ai-assistant.md).

4. **Follow the cross-plane evidence on the topology graph.** The RCA points at a
   node or edge — now see it in the network's *shape*. The topology graph stitches
   every plane (paths, the service map, routing, device telemetry) into one graph of
   nodes and edges, and it is *versioned*, so you can rewind it to the moment the
   incident opened. Read the live graph, or the graph as it was at time `t`:

   ```sh
   # The current graph for your tenant.
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     https://control.example/v1/topology

   # The graph as it existed when the incident opened (rewind to a past moment).
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     "https://control.example/v1/topology?at=2026-06-22T14:00:00Z"
   ```

   You observe a layout-agnostic list of nodes (each with `id`, `kind`, `label`) and
   edges (each with `from`, `to`, `kind`), plus a *coverage block* telling you which
   planes reported — read it like the number of weather stations behind a forecast,
   and trust the picture in proportion to how much reported. If topology is not wired
   on this deployment you get `topology_running: false` with empty lists rather than
   an error. Powered by [topology and change
   intelligence](../features/topology-and-change.md).

5. **Resolve and acknowledge.** You found the cause; the fault is fixed. Claim the
   alert so the next person knows it is owned. *Acknowledge* is signing the station
   logbook — it records who owns the alert and changes nothing about evaluation or
   delivery. (It is not *silence*, which hushes notifications but leaves the alarm
   light on.) Re-read the active list to confirm the engine's updated view:

   ```sh
   # Re-read active alerts to confirm operator state after the fix (needs alert.read).
   curl --cacert ./certs/ca.crt -H "Authorization: Bearer $TOKEN" \
     https://control.example/v1/alerts/active
   ```

   You observe the series now carrying its operator state, and once the underlying
   condition clears it leaves the firing list and you get the recovery notification.
   Powered by [alerting and incidents](../features/alerting-and-incidents.md).

## You're done when

The incident carries a probable root cause with citations that each resolve to a
real signal in your tenant, you have confirmed the supporting evidence on the
(rewound) topology graph, and the firing alert is acknowledged — owned by a named
human and on its way to clearing once the fix lands. The page that woke you up is
now a closed loop with a paper trail.

## Next

When the cause is not a deploy or a route flip but something hostile — a suspicious
flow, a certificate gone bad — follow the sibling journey,
[threat response](./threat-response.md), which starts from a confidence-scored
detection instead of an SLO breach. Unfamiliar term anywhere above? The
[glossary](../glossary.md) defines RCA, SLO, tenant, and the rest.

**Journey:** J2 · **Visits:** F8, F9, F13, F17, F40, F42
