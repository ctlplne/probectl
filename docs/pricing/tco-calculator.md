# Offline pricing and self-hosted TCO calculator

The calculator answers a deliberately boring buyer question: **“If I run this
myself, what must I pay for, and which numbers are still guesses?”** It reads a
local JSON worksheet and writes a local report. It has no network client, does
not read probectl runtime telemetry, and does not phone home.

## Run it

From the repository root:

```bash
go run ./ee/cmd/probectl-tco \
  -input docs/pricing/tco-inputs-2026-08-09.json \
  -format markdown

go run ./ee/cmd/probectl-tco \
  -input docs/pricing/tco-inputs-2026-08-09.json \
  -format json
```

The Markdown snapshot is
[`tco-output-2026-08-09.md`](tco-output-2026-08-09.md). JSON is the canonical
output because every line contains:

- the exact formula;
- the input value and unit;
- provenance, date, and source for every known input; and
- `value: null` plus `unknown_inputs` when an input is unknown.

The input decoder rejects unknown JSON fields, known values without provenance,
and prices without an as-of date. A missing number is never silently changed to
zero.

## Founder recommendation encoded in revision 1

This is a **planning recommendation, not a quote**:

| Plan | Recommended planning input | Why |
|---|---:|---|
| Core | **$0** | The MPL-2.0 five-plane core remains deliberately free. |
| Enterprise | **$24,000/year per self-hosted deployment**, flat; planning tenant band 100 | The buyer already pays its own infrastructure, so a predictable flat license is easier to budget than telemetry tax. |
| MSP | **$12,000/year platform + $15/peak-agent-month**, planning tenant band 1,000 | Peak agents are already measured locally, are understandable, and do not punish high telemetry fidelity. There is no ingest-byte fee. |

The tenant band controls new provisioning; it never drops telemetry. MSP
metering stays local and leaves only through an operator-run export. The MSP
resells under the probectl brand; white-label identity replacement is not
offered. Final rates, discounts, support commitments, reseller language, and
commercial license terms still need real design-partner evidence and counsel.

## Formula map

The calculator builds the worksheet in this order:

```text
agents = tenants * sites_per_tenant * agents_per_site
tests = agents * tests_per_agent
sampled_raw_ingest = agents * raw_ingest_gb_per_agent_day * sampling_fraction * sampling_multiplier
logical_retained = sampled_raw_ingest * retention_days * retention_multiplier / compression_ratio / 1000
hot_retained = logical_retained * hot_replication * replication_multiplier
backup_retained = logical_retained * backup_replication
query_vcpu = query_rps * query_load_multiplier * cpu_seconds_per_query / target_cpu_utilization
compute = (base_vcpu + query_vcpu) * vcpu_month + ram_gib * ram_gib_month
hot_storage = hot_retained * hot_storage_tb_month
backup_storage = backup_retained * backup_tb_month
operator_labor = (operator_hours_base_month + tenants * operator_minutes_tenant_month / 60) * operator_hour
support_labor = tenants * support_hours_tenant_month * support_hour
migration_amortized = migration_hours * migration_hour / migration_amortization_months
infrastructure = compute + hot_storage + backup_storage
self_hosted_tco_before_license = infrastructure + operator_labor + support_labor + migration_amortized
infrastructure_per_logical_retained_tb = infrastructure / logical_retained
monthly_license = base_annual_usd / 12 + agents * per_peak_agent_monthly_usd
monthly_tco = self_hosted_tco_before_license + monthly_license
effective_tenant_month = monthly_tco / tenants
```

“Retained TB” means one logical compressed copy. `hot_retained` separately
accounts for replication, preventing a two-copy cluster from pretending it has
one-copy storage economics.

## Sensitivity and honest unknowns

Each 10-, 100-, and 1,000-tenant scenario is evaluated three ways:

| Case | Retention | Sampling | Hot replication | Query load |
|---|---:|---:|---:|---:|
| Lean | 0.5× | 0.25× | 0.5× | 0.5× |
| Baseline | 1× | 1× | 1× | 1× |
| High | 3× | 1× | 1.5× | 2× |

Revision 1 intentionally leaves `measured_operator_hours_month` unknown. The
calculator shows that measured line as `null`; the planning TCO uses a separately
labeled labor hypothesis. Replace it after the MSP design-partner operations
study. Likewise, compression and ingest volume are engineering assumptions
until the L/XL/XXL runs land. Their provenance says that directly.

Reconciliation map:

| Backlog input | Worksheet cell | Current state |
|---|---|---|
| BL-022 invoice reconciliation | MSP peak-agent unit and support input | Contract shape implemented; real invoice remains design-partner evidence. |
| BL-028 retention cost | ingest, compression, retention, replicas, storage price | Formula and scenarios complete; L/XL/XXL replacement measurements remain external proof. |
| BL-030 host overhead | base vCPU/RAM and measured operator hours | Editable hypothesis; live Linux/reference-cluster measurement remains external proof. |
| BL-034 upgrade/restore | operator and migration hours | Editable hypothesis; replace with the representative drill receipt. |

Do not use a cheaper number obtained by weakening tenant isolation, TLS, audit,
backup, or redaction. Those are product boundaries, not sensitivity knobs.
