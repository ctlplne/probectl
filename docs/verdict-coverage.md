# Verdict coverage — why an empty screen has to say which kind of empty it is

## What it is

probectl reports what it observed. Every one of those reports has the same failure
mode, and it is a quiet one: **an empty answer means two completely different things,
and only one of them is good news.**

"No threats on your network" and "nothing was watching your network" produce the same
empty table. "Your egress costs nothing" and "no flow data ever arrived" produce the
same £0.00. A monitoring product that hands you the reassuring reading for free is
worse than no monitoring at all, because you stop looking.

So probectl's rule is: **a surface that reports what was observed must also report
what was observing.** Not as a footnote — as a field in the response, next to the
data, on the same screen.

Think of a rain gauge. An empty gauge means no rain *only if* the gauge was outside
and upright all week. A gauge that cannot tell you whether it was outside is not a
measurement, it is a container.

## The two declarations

There are exactly two ways an observation report can mislead you, so there are two
things it has to declare.

**Provenance — was anything measuring?**

A boolean or a structure saying whether the producer behind this surface exists and
is running in this deployment, for this tenant. In the API these are the
`*_running` and `*_configured` flags (`collector_running`, `ingest_running`,
`correlation_running`, `change_ingest_configured`, …) plus the richer forms:
`coverage`, `methodology`, `measurement_fidelity`, `silent_planes`, `freshness`.

**Completeness — is this all of it?**

Every list is bounded; a bound that the response does not mention turns "the newest
500" into "all of them". These are `effective_limit`, `truncated`, `next_cursor`.

A surface must declare provenance. If it applies a bound, it must also declare
completeness.

## How each surface does it

| Surface | Route | Declares |
|---|---|---|
| Synthetic results | `GET /v1/results/latest`, `/v1/results/history` | `collector_running` |
| Endpoint attribution | `GET /v1/endpoints` | `collector_running` |
| Flow analytics | `GET /v1/flows/top`, `/capacity`, `/anomalies`, `/ingest-quality` | `ingest_running` |
| Device telemetry | `GET /v1/device/*`, `/v1/devices` | `collection_running`, `metrics_running`, `topology_running`, `partial_reasons` |
| eBPF service map | `GET /v1/ebpf/service-map` | `ebpf_running` |
| BGP events | `GET /v1/bgp/events` | `bgp_running` |
| Incidents | `GET /v1/incidents`, `/v1/incidents/{id}/changes` | `correlation_running` + bound |
| Change timeline | `GET /v1/changes` | `change_ingest_configured`, `config_archive_running` + bound |
| Agent fleet | `GET /v1/agents` | `agent_transport_running` |
| Alerting | `GET /v1/alerts/active`, `/maintenance`, `/{id}/evaluations` | `evaluator_running`, `persistence_running`, `freshness` |
| SLOs | `GET /v1/slos` | `slo_running` |
| Cost | `GET /v1/cost/summary` | `cost_running`, `priced`, `zones_mapped`, `pricing_source`, `data_since` |
| Carbon | `GET /v1/carbon` | `carbon_running`, `methodology.measured` (always false — these are estimates) |
| TLS posture | `GET /v1/tls/posture` | `collector_running`; per item `state`, `visibility`, `capture`, `confidence`, `freshness` |
| Threat detections | `GET /v1/threat/detections` | `detections_running` |
| Compliance | `GET /v1/compliance` | `compliance_running`, `coverage` |
| Path | `GET /v1/tests/{id}/path`, `/path/history` | `measurement_fidelity`, `destination_reached` |
| RCA / assistant | `POST /v1/ai/ask` | `silent_planes`, `degraded`, `root_cause_grounded`, `confidence` |
| Coverage debt / vantages | `GET /v1/coverage/*` | `evidence_running`, `partial_reasons`, `as_of` |
| On-call, SIEM | `GET /v1/oncall/status`, `/v1/siem/status` | `configured`, `dispatcher_running`, `siem_running` |

Surfaces that return rows the caller or an operator **created** — alert rules,
dashboards, directory users, API tokens, tests, the audit log — declare nothing,
because there is nothing to declare: an empty list means you have not created any,
and that is unambiguous.

## What the UI does with it

`web/src/data/classifySurfaceTruth.ts` turns those fields into what a person sees,
and its priority order is the contract in miniature:

1. demo data never masquerades as live;
2. a 403 never masquerades as no data;
3. an error or a degraded producer is shown as degraded;
4. **a producer that is not running is `blocked`, never a zero-valued chart**;
5. a healthy producer with an empty window is `quiet`;
6. only then is it `ready-no-data`.

This is why the server has to supply `producerRunning`. The UI cannot invent it, and
without it every empty surface collapses into the most flattering of those six.

## How it is enforced

`TestEveryObservationSurfaceDeclaresItsCoverage` (`internal/control/verdict_coverage_test.go`)
keys on the *shape* of the response, not on a list of interesting routes: every `/v1`
operation whose 200 body carries an `items` or `summary` envelope must be classified
as `verdict` (it reports what was observed — then it must declare provenance, and
completeness if it is bounded) or `record` (it returns rows someone created).

A new endpoint with an items envelope fails that test until somebody classifies it.
That is the point: the fields do not rot, the classification does — so the
classification is what the gate holds.

## What went wrong before this was a contract

Every one of these was found by driving the product, not by reading it:

- **DPR-150** — onboarding reported `flow-analytics`, `otlp` and `device-telemetry`
  as "engine is running and waiting for tenant data" for a tenant whose flow
  exporters were delivering, whose quality receipts existed and whose device
  collections were succeeding. The three verdicts were literal `false` constants. The
  same payload said `producers[flow].state = ready` two fields away.
- **DPR-151** — `/v1/incidents` silently stopped at 500 rows and `/v1/changes` at 200,
  each presenting a bounded page as the whole set.
- **DPR-152** — during a real fault (the flow agent scaled to zero for ten minutes),
  `/v1/flows/top`, `/capacity` and `/anomalies` each returned an empty list with no
  flag of any kind — the same bytes a tenant with no traffic gets.

## Related

`docs/quality/coverage.md` (surface coverage: every capability declares native /
federated / none-by-design) · `docs/features/ai-assistant.md` (silent planes in RCA) ·
`docs/compliance/` (coverage caveats inside signed evidence).
