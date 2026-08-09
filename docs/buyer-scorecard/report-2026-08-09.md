# Buyer bake-off report

Catalog: `2026-08-09-repository-evidence-2` · profile: `2026-08-09-msp-design-partner-template-1` · archetype: `self-hosted MSP design partner`

## Buyer-owned volumes

| Input | Value | Note |
|---|---:|---|
| agents_per_site | 5.00 count |  |
| flow_events_per_second | 200000.00 events/second | replace with the buyer's measured peak |
| migration_objects | 10000.00 objects | tests, agents, users, policies, integrations, and dashboards |
| operator_hourly_usd | 125.00 USD/hour | replace with loaded labor cost |
| retention_days | 30.00 days |  |
| sites_per_tenant | 1.00 count |  |
| tenants | 100.00 count | edit without changing catalog facts |
| tests_per_agent | 4.00 count |  |

## Scenario cells

| Scenario | Candidate | Weight | Status | Evidence | Notes |
|---|---|---:|---|---|---|
| Intermittent ISP proof | probectl | 5.00 | **pass** | [evidence package contract](../../docs/incident-evidence.md); [tenant-scoped export integration](../../internal/control/incidentevidence_integration_test.go); [offline package verification](../../internal/evidence/package_test.go) | Repository golden fixture passes; a customer-site pilot remains separate field evidence. |
| Remote-user fault-domain attribution | probectl | 3.00 | **unknown** | [provisional synthetic attribution corpus](../../internal/endpoint/attribution_test.go); [consent and provenance contract](../../docs/endpoint-dem.md) | The algorithm and 0.80 floor are implemented, but the required approved representative corpus is not yet a real-user study. |
| MSP onboarding and PSA lifecycle | probectl | 5.00 | **unknown** | [signed PSA retry and lifecycle reconciliation](../../internal/control/notify_integration_test.go); [vendor-neutral PSA contract](../../docs/oncall-itsm.md) | The software path passes; onboarding time and vendor-specific workflow remain unknown until the first MSP design partner. |
| Route change to traffic-impact incident | probectl | 4.00 | **pass** | [cross-plane tenant-scoped correlation gate](../../internal/incident/correlation_gate_test.go); [cited route and traffic evidence contract](../../docs/ai-rca.md) | Repository scenario evidence passes; buyer-scale timing still follows the selected volume profile. |
| Alert cascade grouping and reversal | probectl | 4.00 | **pass** | [explainable grouping, detach, reversal, and tenant boundary](../../internal/incident/correlation_override_test.go); [forced-RLS restart and audit lifecycle](../../internal/control/incidents_integration_test.go); [authorized incident-room create and reverse journey](../../web/src/test/incidents.test.tsx); [grouping, maintenance, and override operator contract](../../docs/alerting.md) | Repository unit, real-PostgreSQL integration, and UI journey evidence pass; the deterministic match confidence is explicitly not a root-cause probability. |
| Upgrade, restore, rollback, and regional failover | probectl | 5.00 | **unknown** | [local backup and restore results](../../docs/ops/backup-restore-results.csv); [local compose failover result](../../docs/ops/failover-results.csv) | Local mechanics have receipts; the requested v0.5.0-to-current two-region Kubernetes drill is not yet a representative receipt. |
| Transparent self-hosted cost and retention | probectl | 5.00 | **pass** | [offline formula and provenance contract](../../docs/pricing/tco-calculator.md); [editable USD input revision](../../docs/pricing/tco-inputs-2026-08-09.json); [10/100/1,000 scenario output](../../docs/pricing/tco-output-2026-08-09.md) | Calculator behavior passes; engineering assumptions stay labeled until external scale and operations measurements replace them. |
| Intermittent ISP proof | buyer incumbent | 5.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |
| Remote-user fault-domain attribution | buyer incumbent | 3.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |
| MSP onboarding and PSA lifecycle | buyer incumbent | 5.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |
| Route change to traffic-impact incident | buyer incumbent | 4.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |
| Alert cascade grouping and reversal | buyer incumbent | 4.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |
| Upgrade, restore, rollback, and regional failover | buyer incumbent | 5.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |
| Transparent self-hosted cost and retention | buyer incumbent | 5.00 | **unknown** | — | Buyer supplies an evidence link from its own evaluated incumbent. |

## Score eligibility

| Candidate | Known coverage | Weighted pass rate | Ranking | Blocking cells |
|---|---:|---:|---|---|
| probectl | 58.06% | UNKNOWN | INELIGIBLE | msp-onboarding-psa:unknown, remote-user:unknown, upgrade-restore:unknown |
| buyer incumbent | 0.00% | UNKNOWN | INELIGIBLE | alert-cascade:unknown, cost:unknown, isp-proof:unknown, msp-onboarding-psa:unknown, remote-user:unknown, route-flow-incident:unknown, upgrade-restore:unknown |

Unknown and unsupported cells are never scored as zero. A candidate is ranking-eligible only when every weighted scenario is an evidence-backed pass or fail. Change the separate buyer profile to change volumes or weights; do not rewrite catalog facts.
