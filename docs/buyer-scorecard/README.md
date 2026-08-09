# Buyer bake-off and migration scorecard

This is an evidence ledger, not a marketing comparison. It asks every candidate
to run the same seven jobs with the buyer's real volumes. A cell may be `pass`,
`fail`, `unknown`, or `unsupported`. Only evidence-backed pass/fail cells are
scored, and **any unknown or unsupported cell makes the candidate ineligible for
ranking**. Missing data never becomes a convenient zero.

Files:

- [`catalog-2026-08-09.json`](catalog-2026-08-09.json) contains fixed scenarios,
  acceptance criteria, current candidate results, evidence links, and non-goals.
- [`msp-design-partner-profile.json`](msp-design-partner-profile.json) contains
  only buyer-editable volumes and weights.
- [`report-2026-08-09.md`](report-2026-08-09.md) is the reproducible summary.

Run locally:

```bash
go run ./cmd/probectl-scorecard \
  -catalog docs/buyer-scorecard/catalog-2026-08-09.json \
  -profile docs/buyer-scorecard/msp-design-partner-profile.json \
  -format markdown
```

Use `-format json` for a machine-readable result. The command only reads the two
named local files and writes stdout; it has no network client and does not
collect confidential product data.

## Design-partner procedure

1. Copy the profile and replace tenant, site, agent, flow, retention, migration,
   and labor volumes. Adjust weights to the buyer's priorities.
2. Do **not** alter the fixture or acceptance criteria for one candidate. If the
   buyer changes a job, version the catalog and rerun every candidate.
3. Run the fixture. Record exact commands, timestamps, version/SHA, environment,
   data volume, pass/fail thresholds, and links to artifacts.
4. Replace an unknown incumbent cell only with the buyer's direct evidence. Do
   not paste vendor adjectives or infer a result from a feature page.
5. Record migration objects and human steps, including dashboards, alert rules,
   users, SSO, agents, tests, retention, ticketing, and runbooks. “Has an API” is
   not a migration-time measurement.
6. Compare candidates only when the report says both are ranking-eligible.

The initial profile is the recommended first MSP design-partner shape. It gives
the highest weights to customer ISP proof, MSP lifecycle/PSA, upgrade/restore,
and transparent cost. Current probectl unknowns stay visible, and the incumbent
is deliberately all unknown until a buyer supplies its own evidence. That is the
honest starting line.
