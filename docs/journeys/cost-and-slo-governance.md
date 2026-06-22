# Journey J5 — Govern cost, SLOs and sustainability

You run a platform and you own its budget. Five engines already read the
telemetry probectl collects; this page walks the path that turns that telemetry
into answers a finance lead and a leadership team can act on: a reliability
promise probectl watches, a per-tenant view of what traffic costs, an estimate
of the carbon spent moving bytes, governed retention, and a report you hand to
finance. A **tenant** is one isolated customer or organization — every number on
this path is scoped to one. Terms of art (FinOps, egress, SLO, error budget) are
in the [glossary](../glossary.md).

## Who this is for

A platform owner or FinOps lead — the practice of making spend visible and tying
it to the team that creates it. You hold the budget and the reliability promises,
you do not necessarily run the agents. You want cost, reliability, and
sustainability visible per tenant, and retention under control.

## Before you start

- A control plane is reachable over HTTPS and you can read its API. The examples
  pass `--cacert ca.crt` so `curl` trusts a self-signed certificate; drop it
  against a publicly trusted certificate.
- At least one tenant has flow data and synthetic probes behind it. If it does
  not yet, stand one up first via [stand up and isolate a tenant](./tenant-setup.md)
  — empty stores answer with zeros, not errors.
- You hold the metrics-read permission (cost and carbon need it) and admin rights
  for a governed export.
- For cost in dollars, you have declared CIDR (Classless Inter-Domain Routing — a
  way of naming an address range by prefix) zone and service rules. Without them
  the cost engine tracks bytes but never invents a dollar figure.

## The path

1. **Define an SLO and tie it to business impact.** A Service Level Objective
   (SLO) turns a promise like "checkout succeeds 99% of the time" into something
   probectl watches continuously. Write it as a standard OpenSLO document, label
   it with the owning team for roll-up, point `PROBECTL_SLO_DIR` at its directory,
   then read its status. probectl evaluates a deliberate subset of OpenSLO and
   rejects anything outside it loudly at load time.
   ```sh
   curl --cacert ca.crt "https://control.example/v1/slos"
   ```
   You observe attainment versus objective, error budget remaining, total events,
   a `cold_start` flag, and per-window burn rates with their firing state. A new
   SLO reports `cold_start: true` until it has seen 50 events, rather than paging
   on statistical noise. Powered by [cost, reliability, chaos and carbon](../features/cost-slo-and-chaos.md).

2. **Watch egress and observability cost by tenant.** Egress is traffic that
   leaves a boundary — an availability zone, a region, or the provider's network —
   and that is what clouds bill for, so where a byte travels matters more than how
   many there are. The cost engine resolves each flow end to a zone, classifies
   it, prices the bytes against published list rates, and attributes the result to
   a service and team.
   ```sh
   curl --cacert ca.crt "https://control.example/v1/cost/summary"
   ```
   You observe totals broken down by class, service, and team; the top "chatty"
   cross-zone conversations; a 7-day hourly trend; budget status; and the honesty
   flags `priced` and `zones_mapped`. With no price table you see `priced: false`
   and byte counts with no dollars — that is correct, not a failure. This is
   attribution at list rates, not your cloud invoice. Powered by [cost, reliability, chaos and carbon](../features/cost-slo-and-chaos.md).

3. **Track carbon and power (an estimate).** The carbon engine reuses the same
   flow stream and the same owner attribution as cost, so the dollar view and the
   carbon view always agree on who owns which traffic. Set your utility's grid
   intensity first, since it varies enormously by region, then read the estimate.
   ```sh
   export PROBECTL_CARBON_GRID_GCO2E=230   # your utility's published gCO2e/kWh
   curl --cacert ca.crt "https://control.example/v1/carbon"
   ```
   You observe totals in kilowatt-hours and grams of carbon, the same
   class/service/team breakdown as cost, a 7-day trend, and a methodology block
   stating `measured: false`. Be honest about this with leadership: these are
   coefficient-based estimates of transmission energy, good for relative
   attribution and trends, never an audited absolute footprint, and a single grid
   figure applies per deployment. Powered by [cost, reliability, chaos and carbon](../features/cost-slo-and-chaos.md).

4. **Apply governance: retention, redaction, residency.** Governance is one view
   per tenant over how long data lives, how sensitive values are masked, and where
   data sits. An IP address defaults to personally identifiable information,
   because under privacy law it is personal data; when masking is active the
   default strategy keeps a coarse network prefix and drops credentials entirely.
   Each store carries its own retention clock. Set these so the cost and carbon
   trends above retain exactly as long as policy allows. Powered by [running probectl in production](../features/operations.md).

5. **Export a report for finance and leadership.** Take a governed, masked export
   of the tenant's data — the same numbers, packaged for someone outside the
   platform team.
   ```sh
   curl --cacert ca.crt "https://control.example/v1/lifecycle/export?redact=true" -o tenant-export.tar.gz
   ```
   You observe a gzipped archive whose manifest carries `"redacted": true`: IP
   addresses appear as a coarse prefix such as `203.0.113.0/24`, emails as
   `a***@domain`, and credentials are gone, while counts and protocol names
   survive. Hand this to finance alongside the cost summary. Powered by [running probectl in production](../features/operations.md).

## You're done when

- An SLO is tracked, reporting attainment, error budget remaining, and burn-rate
  firing state per tenant.
- Cost is visible per tenant, broken down by class, service, and team, with the
  `priced` and `zones_mapped` honesty flags telling you whether dollars are real.
- A carbon estimate is visible per tenant, labeled `measured: false`.
- Retention, redaction, and residency are governed, and a masked export is in your
  finance team's hands.

## Next

Operate the deployment over its whole life — upgrades, failover, FIPS, support
bundles, and a resilience self-test — in [operate in production](./production-operations.md).

**Journey:** J5 · **Visits:** F41, F42, F48, F34
