# Cost, reliability, chaos & carbon intelligence

## What it is

Four engines that turn the network telemetry probectl already collects into
answers the business cares about: *what is this traffic costing us, are we
keeping our reliability promises, will our monitoring actually catch a real
outage, and what is the environmental footprint of moving these bytes?* All four
read the same observed data — none of them adds a new agent or a new probe — and
all four are scoped to one tenant (one isolated customer or organization) at a
time.

- **Network cost intelligence (FinOps)** puts a dollar figure on observed
  traffic and attributes it to a service and team. **FinOps** is the practice of
  making cloud spend visible and tying it to the team that creates it.
- **Service Level Objectives (SLOs)** turn a reliability promise — "checkout
  succeeds 99% of the time" — into something probectl watches continuously and
  rolls up to the business owner. Definitions are written in **OpenSLO**, an
  open, vendor-neutral SLO file format.
- **Network chaos testing** deliberately injects a known network fault — added
  delay, packet loss, a full outage — to prove your monitoring and SLO alerts
  actually fire when the network breaks.
- **Carbon and power reporting** estimates the electricity and carbon spent
  moving your bytes, for sustainability disclosure.

Terms of art (FinOps, egress, SLO/SLI, error budget) are defined in the
[glossary](../glossary.md).

## Why it exists

Bytes are easy to count; the things that matter about them are not. A flow
record tells you a megabyte crossed the wire — it does not tell you that the
megabyte crossed a region boundary and therefore cost real money, that it ate
into checkout's reliability budget, or that it burned a measurable amount of
grid electricity. These four engines attach that missing meaning.

- **Cost.** Clouds bill for **egress** — traffic that *leaves* a boundary such
  as an availability zone, a region, or the provider's network entirely — so
  *where* a byte travels matters far more than how many bytes there are. A
  "chatty" pair of services quietly talking across a region boundary can run up
  a bill nobody notices until the invoice lands weeks later. This engine surfaces
  that leak in close to real time and points at the team responsible.
- **Reliability.** A dashboard full of green checkmarks does not answer the
  question an executive asks: *how much room do we have left before we break our
  promise, and is something burning that room down right now?* An SLO turns
  reliability into a spendable balance you can reason about.
- **Chaos.** A monitoring platform that has never been shown a real failure is
  itself an untested alarm. You test a smoke detector with a match under a test
  rig, not by setting the corridor on fire — chaos testing is that controlled
  match for your observability.
- **Carbon.** Sustainability disclosure (often called environmental, social, and
  governance, or ESG, reporting) increasingly asks "what is your network
  footprint?" The data to estimate it already flows through probectl.

None of these engines acts on the network. Cost never throttles traffic, SLOs
never block anything, and the carbon view never changes a thing — every output
is a signal a human reads, never an enforcement point.

## How it works

**Cost: classify, then price, then attribute.** Each observed flow has two ends.
probectl resolves each end to a zone or region using operator-declared rules in
**Classless Inter-Domain Routing (CIDR) notation** — a way of naming an address
range by prefix, e.g. `10.0.1.0/24` is 256 addresses. probectl cannot guess your
subnet layout, so you declare it. The most specific rule wins (a `/24` beats an
overlapping `/16`). Each flow then gets a **traffic class**, the bytes are
multiplied by a per-class price, and the result is attributed to a service and
team:

| Class | Meaning | Default rate ($/GiB) |
|---|---|---|
| `same_zone` | both ends in the same zone | 0 (free on the major clouds) |
| `inter_az` | same region, different zones | 0.01 |
| `inter_region` | different regions | 0.02 |
| `internet_egress` | leaves to a public address | 0.09 |
| `unknown` | zones unmapped or unresolvable | unpriced — volume still tracked |

The engine prices *observed volume against published list rates* — think of it as
the taxi's own meter, not your credit-card statement. It tells you who rode where
in real time; reconciling that against the actual cloud invoice stays your
finance team's job. The honesty rules are strict: with no price table it runs in
volume-only mode (bytes attributed, dollars never invented), and every response
carries flags (`priced`, `zones_mapped`) plus the pricing source and an as-of
date, so staleness is visible rather than hidden.

**SLO: a spendable error budget, watched on two clocks.** The thing you measure
is the **service-level indicator (SLI)** — the ratio of good probes to total
probes. The **SLO** is the target you hold it to. If your target is 99%, you are
*allowed* to fail 1% of the time; that 1% is your **error budget**, a balance you
spend as failures happen. **Burn rate** is how fast you spend it:

```text
burn rate = errorRate(window) / (1 − target)
```

Burn rate 1 spends exactly the whole budget over the SLO window and lands on
empty right at the end — sustainable. Burn rate 14.4 spends the whole month's
budget in about two days — an emergency. The hard part is telling a real outage
from a blip, so probectl requires **two** windows — a long one and a short one —
to *both* exceed the threshold before it alerts (a logical AND, the established
Google site-reliability-engineering method). The long window proves the problem
is sustained; the short window proves it is still happening now:

| Tier | Long window | Short window | Burn ≥ | Severity |
|---|---|---|---|---|
| fast | 1h | 5m | 14.4 | page |
| medium | 6h | 30m | 6 | page |
| slow | 3d | 6h | 1 | ticket (warning) |

A brand-new SLO with almost no data would trip every threshold on a single
failure, so the engine stays quiet (reporting `cold_start: true`) until an SLO
has seen at least 50 events in its full window. Alerts latch per episode and
re-arm only after the *long* window drops back under the threshold, so one
outage cannot flap out a stream of pages.

**Chaos: a blast radius the design makes impossible to widen.** The chaos
injector is an in-process relay for datagrams (small connectionless network
packets) that perturbs *only* traffic explicitly addressed to its own listener.
It touches no kernel state, no firewall rules, no agent or tenant traffic, and it
is **not reachable from any application programming interface (API)** — actions
against the network are human-gated by design in probectl, and this one is not
even wired in. A chaos run has a fixed shape: healthy baseline → inject → observe
→ heal → observe. The baseline-first shape is what makes the result evidence — an
alert already firing before the fault proves nothing.

**Carbon: two multiplications, honestly labeled.** The carbon engine reuses the
*same* flow stream and the *same* zone and owner attribution as the cost engine,
so the dollar view and the carbon view always agree on who owns which traffic:

```text
kWh   = (bytes / GiB) × energy-coefficient(traffic class)
gCO2e = kWh × grid intensity (gCO2e/kWh)
```

The energy coefficients (kilowatt-hours per gigabyte) come from published
transmission-energy literature and scale with path locality. Grid intensity (the
carbon your electricity carries) is operator-set — set your real figure, since it
varies enormously by region. Every response is labeled `measured: false`: these
are coefficient-based *estimates* of transmission energy, good for relative
attribution and trends, never an audited absolute footprint. The engine never
pretends otherwise, and like everything else here it is fully local — nothing is
fetched and nothing leaves your network.

## Use it

**Wire up cost classification and attribution** with operator-declared rules, then
set monthly budgets:

```sh
# CIDR → zone (region derived from the trailing zone letter, or set explicitly)
export PROBECTL_COST_ZONES="10.0.1.0/24=us-east-1a,10.9.0.0/16=eu-west-1a"
# CIDR → service:team (this is what makes per-team showback possible)
export PROBECTL_COST_SERVICES="10.0.1.0/24=checkout:payments,10.0.2.0/24=inventory:logistics"
# Monthly USD budgets; a breach raises ONE signal per budget per month
export PROBECTL_COST_BUDGETS="team:payments=500,service:checkout=120"
```

Read the tenant's cost summary:

```sh
curl --cacert ca.crt "https://control.example/v1/cost/summary"
```

What you should observe: totals broken down by class, service, and team; the top
"chatty" zone-pair conversations (a pair is flagged once it crosses 1 GiB of
*paid* cross-zone or cross-region traffic — same-zone and internet traffic do not
count, since the point is internal leaks); a 7-day hourly trend; budget status;
and the honesty flags `priced` and `zones_mapped`. If you have not supplied a
price table, you will see `priced: false` and byte counts with no dollars — that
is correct, not a failure.

**Define an SLO** as a standard OpenSLO document and point `PROBECTL_SLO_DIR` at
the directory holding it. probectl evaluates a deliberate subset and rejects
anything outside it loudly at load time — an SLO you *think* is being tracked
must actually be tracked:

```yaml
apiVersion: openslo/v1
kind: SLO
metadata:
  name: checkout-availability
  labels:
    team: payments            # the business-unit mapping for roll-up
spec:
  service: checkout
  indicator:
    spec:
      ratioMetric:
        good:
          metricSource:
            type: probectl
            spec: { canary_type: http, target: checkout.acme.example, outcome: success }
        total:
          metricSource:
            type: probectl
            spec: { canary_type: http, target: checkout.acme.example }
  timeWindow: [{ duration: 30d, isRolling: true }]
  budgetingMethod: Occurrences
  objectives: [{ target: 0.99 }]
```

Read the tenant's SLO status at `GET /v1/slos`. What you should observe:
attainment versus objective, error budget remaining, total events, the
`cold_start` flag, and per-window burn rates with their firing state. A new SLO
reports `cold_start: true` until it has 50 events.

**Run a chaos self-test** against your own echo path in your own test harness —
start a proxy, point a `udp` or `voice` probe at it, and flip the fault on:

```text
healthy baseline   → SLO quiet, probes pass, latency normal
inject a partition → probes fail for real, the multi-window burn alert fires
heal               → attainment recovers, the alert clears
```

If injecting a known fault does *not* make the alert fire, that is a failure of
the platform's core promise — which is exactly what the self-test is built to
catch.

**Read the carbon estimate** at `GET /v1/carbon`, after setting your grid figure:

```sh
export PROBECTL_CARBON_GRID_GCO2E=230   # your utility's published gCO2e/kWh
curl --cacert ca.crt "https://control.example/v1/carbon"
```

What you should observe: totals in kilowatt-hours and grams of carbon, the same
class/service/team breakdown as cost, a 7-day trend, and a methodology block
stating `measured: false` with the coefficient source and grid figure used.

## Pitfalls & limits

- **Cost is attribution, not your invoice.** The engine prices observed volume at
  list rates; it does not reconcile your actual cloud bill, and full
  billing-API reconciliation is out of scope by design. Treat it as "who is
  generating expensive traffic, and roughly what does it cost."
- **No zone rules means `unknown`, not a guess.** Without CIDR→zone rules every
  flow lands in the `unknown` class with bytes tracked but no dollars. probectl
  never invents a rate or guesses your subnet layout.
- **A malformed price table fails startup on purpose.** Silently mispriced cost
  data is worse than none, so a broken override file refuses to boot. To run with
  no pricing at all, switch to volume-only mode explicitly.
- **SLOs cover the network planes, not your application.** probectl evaluates a
  subset of OpenSLO (ratio metrics, occurrence budgeting, a single rolling
  window, one objective). Application-level instrumentation is out of scope —
  probectl correlates the network, it does not own your app's metrics.
- **Cold-start silence is deliberate.** A low-cadence probe may take a while to
  reach 50 events; until then the SLO honestly reports `cold_start: true` rather
  than paging on statistical noise.
- **Chaos is a self-test, not an API.** The injector cannot be triggered remotely
  and never mutates a live cluster. Transmission-Control-Protocol and
  Hypertext-Transfer-Protocol stream faults and cluster-level chaos
  orchestration (killing pods and nodes) are out of scope — dedicated chaos tools
  own those.
- **Carbon is an estimate, structurally.** Every response is labeled
  `measured: false`. No supported device reports actual wattage today, and the
  engine never fabricates it. Good for relative comparison and trends; not an
  audited footprint. A single grid figure applies per deployment — there is no
  per-region split yet.

## Reference

- **Cost endpoint:** `GET /v1/cost/summary` (needs the metrics-read permission).
  A budget breach raises one `cost.budget_exceeded` signal per budget per month
  into the incident pipeline; it never throttles traffic.
- **Cost config:** `PROBECTL_COST_ENABLED`, `PROBECTL_COST_ZONES`,
  `PROBECTL_COST_SERVICES`, `PROBECTL_COST_BUDGETS`, `PROBECTL_COST_PRICES_FILE`
  (JSON override of the built-in public list rates), `PROBECTL_COST_PRICED`
  (`false` for volume-only mode).
- **SLO endpoints:** `GET /v1/slos` (tenant-scoped statuses), `GET
  /v1/slos/openslo` (the loaded definitions as an OpenSLO YAML stream). Config:
  `PROBECTL_SLO_ENABLED`, `PROBECTL_SLO_DIR`. Burn-rate crossings raise an
  `slo.burn_rate` signal into the incident pipeline.
- **What-if tie-in:** the read-only topology what-if simulation reports
  `impacted_slos` — the SLOs whose service or target sits inside a simulated
  failure's blast radius — so "what breaks if this link dies?" answers in SLO
  terms.
- **Carbon endpoint:** `GET /v1/carbon` (needs the metrics-read permission).
  Config: `PROBECTL_CARBON_ENABLED`, `PROBECTL_CARBON_GRID_GCO2E` (accepted range
  1–5000).
- **Deep dashboarding** for cost is federated to Grafana over the same flow
  series probectl already exposes — there is no separate dashboard surface to
  maintain. See the ecosystem-integrations material.
- **Related capabilities (separate pages):** Alerting and incidents (where these
  signals land); Topology & change (the what-if simulation that reports impacted
  SLOs); Flow analytics (the byte stream cost and carbon both read).

**Covers:** F41, F42, F47, F48
