# ADR: no partner/public active-vantage integration before design-partner proof

- **Status:** accepted
- **Date:** 2026-08-09
- **Decision owner:** founder/product/security
- **Backlog:** BL-046

## Decision

Reject a partner/public **active probe** integration for the current product.
probectl remains customer/MSP-owned-vantage only and keeps the probectl brand.
The already-supported opt-in public outage/routing feeds remain read-only
context; they do not become a substitute probe, a green coverage cell, or an
external party allowed to publish tenant results.

ELI5: a weather map may tell you there is a storm nearby, but only your own rain
gauge proves rain fell at your building. We will keep showing the weather map as
labeled context and keep empty gauge locations visibly empty.

## Why this is the recommendation

The owned-vantage implementation already provides the core buyer outcome:
tenant-bound mTLS agents, explicit site/region labels, cadence evidence, and a
coverage UI that says `uncovered` or `unknown` instead of implying a worldwide
fleet. The frozen research found independent-vantage trust as a strategically
important but thin signal. It did not prove that a specific third-party source
is worth changing the trust, sovereignty, and resale boundary before an MSP
design partner exists.

## Architecture and guardrails

| Concern | Current decision |
| --- | --- |
| tenant identity | active results originate only from a tenant-bound probectl agent/certificate; no public source may assert `tenant_id` |
| no phone-home / air gap | no new default egress or vendor availability dependency; owned probes and core coverage work offline |
| authentication | no third-party result-ingestion credential or signature scheme is added |
| provenance | public feeds remain explicitly `public`/external context; customer results remain `synthetic` or `endpoint` with owned-vantage identity |
| availability | an external feed may be stale/unavailable without breaking tests, incidents, or coverage truth |
| data custody | tenant telemetry stays in the operator's deployment; no probe task or result is sent to a partner |
| product boundary | no probectl-operated public fleet, hosted SaaS, white-label/OEM identity, or implied global coverage |

## AUP/resale and cost

No candidate provider has approved terms in this decision, so redistribution,
commercial/MSP resale, caching, derived-work rights, deletion duties, geographic
restrictions, and attribution are all unknown. Rejecting integration means no
unreviewed AUP becomes a runtime dependency and no per-check/provider bill is
silently introduced. The offline USD model therefore keeps public-vantage
license and operations cost as `unknown`, not `$0`.

## Threat model avoided

A third-party active source would add forged/replayed results, task-target abuse,
tenant-mapping mistakes, cross-customer correlation, malicious response bodies,
partner credential theft, result withholding, timestamp/skew manipulation,
residency leakage, and source outage/rate-limit failure. A future source would
need tenant-first mapping independent of the payload, signed/replay-resistant
receipts, bounded untrusted parsing, TLS verification, cache/provenance, and
graceful degradation. No such surface is added now.

## Product and UX consequence

`docs/outside-in.md`, `GET /v1/coverage/vantages`, the CLI, and the web coverage
panel remain the authoritative story: the operator sees exactly which owned
sites produced fresh evidence, and a missing region stays uncovered. Public
outage context stays opt-in and labeled. Marketing must not say “global probe
network,” “worldwide coverage,” or any equivalent.

## Revisit trigger

Reopen only after a named MSP design partner shows a material uncovered job
that owned deployment cannot reasonably satisfy and names a candidate source.
Before code, require founder approval plus a source-specific AUP/resale memo,
data-flow and threat model, sovereignty/air-gap decision, USD cost case,
retention/deletion plan, and a signed test contract. If approved then, the first
implementation backlog must begin with read-only cached ingestion,
TLS/signature/replay validation, untrusted-input tests, explicit provenance, and
source-outage graceful degradation.
