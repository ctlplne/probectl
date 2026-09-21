# probectl offline TCO report

Input revision: `2026-09-20-no-published-price-2` · currency: `USD` · offline: `true`

| Scenario | Sensitivity | Plan | License / month | TCO / month | Per tenant / month | Cap |
|---|---|---|---:|---:|---:|---|
| 10-tenants | lean | Core | $0.00 | $6160.61 | $616.06 | unlimited |
| 10-tenants | lean | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 10-tenants | lean | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 10-tenants | baseline | Core | $0.00 | $6213.29 | $621.33 | unlimited |
| 10-tenants | baseline | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 10-tenants | baseline | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 10-tenants | high | Core | $0.00 | $6401.33 | $640.13 | unlimited |
| 10-tenants | high | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 10-tenants | high | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 100-tenants | lean | Core | $0.00 | $25170.13 | $251.70 | unlimited |
| 100-tenants | lean | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 100-tenants | lean | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 100-tenants | baseline | Core | $0.00 | $25696.88 | $256.97 | unlimited |
| 100-tenants | baseline | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 100-tenants | baseline | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 100-tenants | high | Core | $0.00 | $27577.27 | $275.77 | unlimited |
| 100-tenants | high | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 100-tenants | high | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 1000-tenants | lean | Core | $0.00 | $150918.84 | $150.92 | unlimited |
| 1000-tenants | lean | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | exceeds_cap |
| 1000-tenants | lean | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 1000-tenants | baseline | Core | $0.00 | $156147.92 | $156.15 | unlimited |
| 1000-tenants | baseline | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | exceeds_cap |
| 1000-tenants | baseline | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |
| 1000-tenants | high | Core | $0.00 | $174874.85 | $174.87 | unlimited |
| 1000-tenants | high | Enterprise | UNKNOWN | UNKNOWN | UNKNOWN | exceeds_cap |
| 1000-tenants | high | MSP | UNKNOWN | UNKNOWN | UNKNOWN | within_cap |

`UNKNOWN` means at least one named input is null; inspect JSON output for the exact formula and unknown inputs. This planning report is not a quote or legal term.
