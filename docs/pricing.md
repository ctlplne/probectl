# Pricing & plans

This is the buyer-facing version of the editions contract. The implementation
source of truth is still the single feature table in
[`internal/license/license.go`](../internal/license/license.go); this page states
the public plan boundary and the metering units without inventing legal terms.

## Public price posture

| Plan | Price posture | Boundary |
|---|---|---|
| Community | **$0** for self-hosted core use | The full five-plane platform: observability, AI assistant and MCP, security/threat signals, topology, cost/SLO, OIDC SSO, SCIM, RBAC/ABAC, per-tenant export/deletion, fairness enforcement, and support-bundle generation. |
| Enterprise | **Fixed annual license by support/governance band** | Validated-module/FIPS distribution, BYOK, governance controls, guarded remediation, and HA support/SLA entitlement; the runtime HA reference deployment remains core. |
| Provider/MSP | **Fixed annual tenant-band license** | Provider plane, siloed/hybrid isolation and residency controls, metering/showback export, white-label, and tenant-band licensing for self-hosted resale. |

The paid posture is intentionally a public fixed-license framework, not a
consumption meter. Enterprise bands are support/governance bands:
`Enterprise-Support`, `Enterprise-Governance`, and `Enterprise-Regulated`.
Provider/MSP bands are licensed tenant-count bands: `Provider-25`,
`Provider-100`, `Provider-500`, and `Provider-Unlimited`. Bespoke procurement can
change contract terms, support response, or reseller commitments, but it does not
change the product billing unit into per-host, per-flow, per-test, per-result, or
per-GB charges.

There is no "SSO tax": OIDC SSO, SCIM, RBAC, and ABAC are core. SAML is not yet
supported, and is tracked as a capability gap rather than a paid downgrade.

There is also no "AI tax": the AI assistant, grounded RCA, semantic query, MCP
server, and deterministic air-gapped engine are core. If you connect a remote
model, that model provider's bill is yours, and probectl only sends tenant
evidence after the explicit egress, redaction, and audit gates pass.

## What is gated

The commercial features are exactly the ones in the license table:

| Plan | Gated features |
|---|---|
| Enterprise | `fips`, `byok`, `governance`, `remediation`, `ha_support` (displayed as HA support/SLA) |
| Provider/MSP | `provider_plane`, `siloed_isolation`, `metering`, `white_label` |

Provider is not an automatic superset of Enterprise. If a provider deal also
needs BYOK or guarded remediation, the signed license grants those as explicit
extras; the code checks each feature by name.

## Metering units

Provider/MSP metering is a showback, capacity-planning, fairness, and MSP
tenant-reporting feed. It does not turn core observability into surprise
per-host, per-flow, or per-GB-at-rest probectl billing.

The units are the same ones documented in [`metering.md`](metering.md):

| Meter | Kind | Unit | How to read it |
|---|---|---|---|
| `agents` | gauge | count | Peak number of registered agents in the period. |
| `tests` | gauge | count | Peak number of configured tests in the period. |
| `results_ingested` | counter | count | Sum of result records ingested in the period. |
| `ingest_bytes` | counter | bytes | Sum of result payload bytes ingested in the period; not retained-GB storage billing. |
| `flow_events` | counter | count | Sum of flow events or batches recorded in the period; not a hidden per-flow core gate. |
| `ai_calls` | counter | count | Sum of AI assistant questions in the period. |

These counters can help an MSP invoice its own customers or plan capacity, but
they are not probectl invoice units. probectl's paid unit is the fixed Enterprise
band or Provider/MSP tenant band.

Quotas use the creation-time controls from the Provider plane (`max_agents`,
`max_tests`). They do not drop telemetry: existing agents keep sending, ingest is
not silently discarded, and pooled fairness remains the layer that protects a
shared deployment under load.

## License and expiry behavior

Commercial activation is offline local math: the signed license file is verified
inside the control plane and never phones home. Unlicensed commercial surfaces are
hidden except for Admin -> Editions, and expired commercial features degrade
read-only after the grace period. Telemetry pipelines keep running.

The legal source-available license text is still a separate counsel-owned
artifact. Until it lands, this page describes product packaging and metering, not
legal rights.
