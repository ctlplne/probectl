# Carbon / power observability (estimate)

## What this is

The sustainability (ESG) view of network traffic: an **estimate** of how much
electricity (kWh) and carbon (gCO2e) the network spends moving your bytes,
broken down by traffic class, service, and team. It is the same idea as
Kepler — attributing energy to workloads — applied to the network plane, and it
is computed entirely from telemetry probectl already has.

It lives in the control plane (`internal/carbon`) and reuses the FinOps engine's
plumbing: the *same* flow stream and the *same* zone/owner attribution, so the
dollar view and the carbon view always agree on who owns which traffic. It is
fully local: no external calls, and the grid carbon intensity is operator-set
configuration — per the no-phone-home rule in the
[Non-negotiables](../CONTRIBUTING.md#non-negotiables), nothing is fetched and
nothing leaves your network.

## The estimate, and its honesty

Two multiplications:

```
kWh   = (bytes / GiB) × kWh-per-GB(traffic class)
gCO2e = kWh × grid intensity (gCO2e/kWh)
```

- **Energy coefficients** — fixed-network transmission energy, from the
  published literature (the Aslan et al. 2017 band and its successors). probectl
  scales the coefficient by path locality, because traffic crossing more network
  hops costs more energy to move. The defaults span roughly 0.004 to 0.06
  kWh/GB:

  | Traffic class | kWh per GB |
  |---|---|
  | `same_zone` | 0.004 |
  | `inter_az` | 0.01 |
  | `inter_region` | 0.03 |
  | `internet_egress` | 0.06 |
  | `unknown` (zones unmapped) | 0.01 (conservative mid-band) |

- **Grid intensity** — `PROBECTL_CARBON_GRID_GCO2E`, the carbon your electricity
  carries per kWh. It defaults to roughly the world average (436 gCO2e/kWh).
  **Set your real figure** — your utility or national grid operator publishes
  it, and it varies enormously by region (a hydro-heavy grid is a fraction of a
  coal-heavy one).
- **Attribution** — the exact same zone and owner maps the FinOps engine uses
  (`PROBECTL_COST_ZONES` / `PROBECTL_COST_SERVICES`), so dollars and grams line
  up on the same services and teams.

**The honesty contract is structural, not a footnote.** Every response carries a
methodology block: `measured: false`, the coefficient source, the grid intensity
used, and a note stating plainly that these are coefficient-based **estimates of
transmission energy**, not measured device power. They are good for relative
attribution ("service A moves ~3× the carbon of service B"), trends over time,
and ESG reporting that *cites its methodology* — they are not audited absolute
footprints, and the engine never pretends otherwise.

## Serving

`GET /v1/carbon` (permission `metrics.read`) — the tenant's totals, the
breakdowns by class / service / team, a 7-day hourly trend, and the methodology
block. In the UI, the **Carbon / energy (estimate)** card folds into the Cost
page — the sustainability sibling of dollar showback. `carbon_running: false`
distinguishes an engine that is not wired in from one that simply has no data
yet.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_CARBON_ENABLED` | `true` | the estimation engine (local-only) |
| `PROBECTL_CARBON_GRID_GCO2E` | `436` | your grid's carbon intensity in gCO2e/kWh (accepted range 1–5000) |

Deferred by design:

- **Device-measured power.** The methodology block's `measured` flag is the
  structural seam for one day distinguishing real device power (e.g. PSU watts
  over SNMP) from coefficient estimates — today it is always `false`, no
  supported device reports watts, and the engine never fabricates them.
- **Per-region grid intensities.** For now a deployment uses one grid figure;
  there is no per-region split.
