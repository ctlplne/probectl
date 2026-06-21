# Operating Cost Model

This page estimates the monthly cost of running probectl itself. It is not the
tenant FinOps feature in [`finops.md`](finops.md), which prices customer network
egress. This is the operator's planning worksheet: compute, storage, query load,
and optional remote-model RCA bursts.

The model is intentionally formula-first. Cloud list prices, discounts, hardware
leases, and reserved capacity vary too much for one table to be universal, so the
tables below use explicit unit assumptions. Swap the assumptions with your own
rates before using the totals for a budget.

## Unit Assumptions

| Unit | Example planning price | Replace with |
| --- | ---: | --- |
| vCPU-month | 25 USD | your VM/Kubernetes node amortized CPU price |
| RAM GiB-month | 4 USD | your node memory price |
| NVMe GiB-month | 0.10 USD | your hot block-storage price |
| Object/WORM GiB-month | 0.023 USD | your backup/object-lock storage price |
| Remote model input | 3 USD / 1M tokens | your provider/model input rate |
| Remote model output | 15 USD / 1M tokens | your provider/model output rate |

Formulas:

```text
compute_month = vcpu * vcpu_month + ram_gib * ram_gib_month
hot_storage_month = retained_hot_gib * nvme_gib_month * replicas
object_storage_month = retained_object_gib * object_gib_month * replicas
monthly_infra = compute_month + hot_storage_month + object_storage_month
host_month = monthly_infra / monitored_hosts
retention_day_delta = rows_per_second * 86,400 * bytes_per_row * replicas * storage_gib_month / 1,073,741,824
query_vcpu = query_per_second * cpu_seconds_per_query / target_cpu_utilization
rca_remote_usd = calls * ((input_tokens / 1,000,000) * input_price + (output_tokens / 1,000,000) * output_price)
```

## Tier Run-Cost Worksheet

These rows tie to the capacity tiers in [`capacity.md`](capacity.md) and the
receipt state in [`scale-gate.md`](scale-gate.md). The example monthly cost is a
starting infrastructure budget before backup copies, support contracts, and
tenant-specific retention overrides.

| Tier | Receipt state | Monitored hosts | Tenants | Planning footprint | Example monthly infra | Example $/host-month |
| --- | --- | ---: | ---: | --- | ---: | ---: |
| S | CI/dev smoke only | 25 | 1 | 10 vCPU, 28 GiB RAM, 300 GiB hot disk | 392 USD | 15.68 USD |
| M | Nightly M guard | 320 | 8 | 56 vCPU, 192 GiB RAM, 5,472 GiB hot disk | 2,715 USD | 8.48 USD |
| L | Pending `make scale-fullstack TIER=L` receipt | 3,200 | 32 | 216 vCPU, 752 GiB RAM, 29,696 GiB hot disk | 11,377 USD | 3.56 USD |
| XL | Pending `make scale-fullstack TIER=XL` receipt | 19,200 | 64 | 784 vCPU, 2,784 GiB RAM, 112,640 GiB hot disk | 42,000 USD | 2.19 USD |
| XXL | Pending `make scale-fullstack TIER=XXL` receipt | 100,000 | 100 | 2,400 vCPU, 9,600 GiB RAM, 600,000 GiB hot disk | 158,400 USD | 1.58 USD |

Do not treat the L/XL/XXL prices as verified throughput prices until the matching
`scale-fullstack` result rows are recorded. The worksheet is tied to those rows
so the cost claim moves with the performance claim.

## Retention Cost

Retention is usually the biggest variable cost because flow/eBPF rows dominate
volume. Use the bytes-per-row constants from [`capacity.md`](capacity.md).

At 0.10 USD/GiB-month hot storage and one replica:

| Change | Stored class | Monthly delta |
| --- | --- | ---: |
| Add 1 retention day at 1,000 rows/s | Synthetic result, 1,536 B | 12.36 USD/month |
| Add 1 retention day at 1,000 rows/s | Flow/eBPF record, 512 B | 4.12 USD/month |
| Add 1 retention day at 100 rows/s | Control/event row, 2,048 B | 1.65 USD/month |
| Add 1 retention day at 10 rows/s | Audit row, 4,096 B | 0.33 USD/month hot + 0.08 USD/month WORM |

Example: moving a tenant from 30 to 90 days of 10,000 flow rows/s adds roughly
`60 * 10 * 4.12 = 2,472 USD/month` of hot ClickHouse storage before replicas.
That is why retention belongs in the tenant governance discussion, not only in a
storage alarm.

## Query Load Cost

Query load becomes dollars when it forces more CPU or shards. Measure
`cpu_seconds_per_query` from pprof or node CPU divided by successful queries for
the route class, then use:

```text
query_vcpu = query_per_second * cpu_seconds_per_query / 0.65
query_month = query_vcpu * vcpu_month
```

Use 65% target CPU utilization so bursts and compaction have room.

| Query class | Starting CPU seconds/query | Cost trigger |
| --- | ---: | --- |
| Simple tenant list/status | 0.002 | Add API replicas when p95 rises before datastore p95 rises. |
| Flow/topology/capacity query | 0.020 | Add ClickHouse/TSDB shards when p95 exceeds hot-path targets. |
| Wide RCA evidence gather | 0.200 | Add query budget or cache when incident storms hit the AI surface. |

The cost guard in [`fairness.md`](fairness.md) protects shared tenants from one
caller turning query CPU into a platform-wide bill.

## RCA And Model-Call Bursts

The default AI path is local/builtin, so remote model cost is 0 USD and no tenant
data leaves the operator network. Remote models are opt-in and consent-gated;
the egress behavior is documented in [`ai-egress.md`](ai-egress.md).

When a remote model is enabled, budget for incident storms:

| Scenario | Calls | Tokens/call | Example model cost |
| --- | ---: | --- | ---: |
| One incident, one answer | 1 | 6k input + 1k output | 0.03 USD |
| 100-incident storm, two answers each | 200 | 6k input + 1k output | 6.60 USD |
| 1,000 broad RCA calls | 1,000 | 30k input + 3k output | 135.00 USD |

Formula:

```text
remote_model_cost = calls * ((input_tokens / 1,000,000) * input_rate + (output_tokens / 1,000,000) * output_rate)
```

The real limiter is often not dollars but privacy and audit posture: remote RCA
must pass the AI egress gate, tenant consent, redaction policy, and audit trail.

## Budget Review Loop

Run this loop whenever scale rows, retention, or tenant mix changes:

1. Copy the latest verified capacity row from `docs/scale-gate.md`.
2. Replace the unit prices above with your current infrastructure and model
   rates.
3. Compute hot storage from actual row rates and retention using
   `docs/capacity.md`.
4. Compute query CPU from measured query CPU/query, not request count alone.
5. Divide by monitored hosts and tenants, then compare against your target gross
   margin or sovereign-operator budget.

If a budget does not work, the safest knobs are retention, tenant sharding, and
query budgets. Do not solve cost by weakening tenant isolation, TLS, audit, or
redaction.
