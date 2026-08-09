# probectl offline TCO report

Input revision: `2026-08-09-founder-recommendation-1` · currency: `USD` · offline: `true`

| Scenario | Sensitivity | Plan | License / month | TCO / month | Per tenant / month | Cap |
|---|---|---|---:|---:|---:|---|
| 10-tenants | lean | Core | $0.00 | $6160.61 | $616.06 | unlimited |
| 10-tenants | lean | Enterprise | $2000.00 | $8160.61 | $816.06 | within_cap |
| 10-tenants | lean | MSP | $1750.00 | $7910.61 | $791.06 | within_cap |
| 10-tenants | baseline | Core | $0.00 | $6213.29 | $621.33 | unlimited |
| 10-tenants | baseline | Enterprise | $2000.00 | $8213.29 | $821.33 | within_cap |
| 10-tenants | baseline | MSP | $1750.00 | $7963.29 | $796.33 | within_cap |
| 10-tenants | high | Core | $0.00 | $6401.33 | $640.13 | unlimited |
| 10-tenants | high | Enterprise | $2000.00 | $8401.33 | $840.13 | within_cap |
| 10-tenants | high | MSP | $1750.00 | $8151.33 | $815.13 | within_cap |
| 100-tenants | lean | Core | $0.00 | $25170.13 | $251.70 | unlimited |
| 100-tenants | lean | Enterprise | $2000.00 | $27170.13 | $271.70 | within_cap |
| 100-tenants | lean | MSP | $8500.00 | $33670.13 | $336.70 | within_cap |
| 100-tenants | baseline | Core | $0.00 | $25696.88 | $256.97 | unlimited |
| 100-tenants | baseline | Enterprise | $2000.00 | $27696.88 | $276.97 | within_cap |
| 100-tenants | baseline | MSP | $8500.00 | $34196.88 | $341.97 | within_cap |
| 100-tenants | high | Core | $0.00 | $27577.27 | $275.77 | unlimited |
| 100-tenants | high | Enterprise | $2000.00 | $29577.27 | $295.77 | within_cap |
| 100-tenants | high | MSP | $8500.00 | $36077.27 | $360.77 | within_cap |
| 1000-tenants | lean | Core | $0.00 | $150918.84 | $150.92 | unlimited |
| 1000-tenants | lean | Enterprise | $2000.00 | $152918.84 | $152.92 | exceeds_cap |
| 1000-tenants | lean | MSP | $76000.00 | $226918.84 | $226.92 | within_cap |
| 1000-tenants | baseline | Core | $0.00 | $156147.92 | $156.15 | unlimited |
| 1000-tenants | baseline | Enterprise | $2000.00 | $158147.92 | $158.15 | exceeds_cap |
| 1000-tenants | baseline | MSP | $76000.00 | $232147.92 | $232.15 | within_cap |
| 1000-tenants | high | Core | $0.00 | $174874.85 | $174.87 | unlimited |
| 1000-tenants | high | Enterprise | $2000.00 | $176874.85 | $176.87 | exceeds_cap |
| 1000-tenants | high | MSP | $76000.00 | $250874.85 | $250.87 | within_cap |

`UNKNOWN` means at least one named input is null; inspect JSON output for the exact formula and unknown inputs. This planning report is not a quote or legal term.
