# Carbon / power observability (S48, F48)

The ESG view of network traffic: **estimated** transmission energy (kWh)
and carbon (gCO2e) per traffic class, service, and team — the Kepler idea
applied to the network plane, computed entirely from telemetry probectl
already has. Local-only: no external calls; the grid intensity is
operator-set config (sovereignty, guardrail 2).

## The estimate (and its honesty)

```
kWh   = bytes / GiB × kWh-per-GB(traffic class)
gCO2e = kWh × grid intensity (gCO2e/kWh)
```

- **Coefficients**: fixed-network transmission energy in the published
  ~0.004–0.06 kWh/GB band (Aslan et al. 2017 and successors), scaled by
  path locality — same-zone cheapest, internet egress dearest. Unmapped
  zones use a conservative mid-band value.
- **Grid intensity**: `PROBECTL_CARBON_GRID_GCO2E` (defaults to the world
  average ~436 — **set your real grid figure**; your utility or national
  TSO publishes it).
- **Attribution**: the SAME zone/owner mapping as the FinOps engine
  (`PROBECTL_COST_ZONES` / `PROBECTL_COST_SERVICES`) — dollars and grams
  agree on who owns which traffic.

**The honesty contract (structural):** every response carries the
methodology block — `measured: false`, the coefficient source, the grid
intensity, and the note that these are coefficient-based ESTIMATES of
transmission energy, not measured device power. They are suitable for
relative attribution, trends, and directionally-honest ESG reporting that
cites its methodology — not for audited absolute footprints.

## Serving

`GET /v1/carbon` (metrics read): totals + by class/service/team + the
7-day hourly trend + methodology. The **Carbon / energy (estimate)** card
folds into the Cost page (the ESG sibling of showback). `carbon_running:
false` distinguishes an unwired engine.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PROBECTL_CARBON_ENABLED` | `true` | the estimation engine (local-only) |
| `PROBECTL_CARBON_GRID_GCO2E` | `436` | your grid's carbon intensity, gCO2e/kWh |

Deferred by design: device-measured power (S39 SNMP devices that report
PSU watts could upgrade estimates to measurements per device — the seam
exists; no supported device reports watts today, and the engine never
fabricates them), and per-region grid intensities (one deployment, one
grid figure for now).
