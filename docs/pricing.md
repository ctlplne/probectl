# Pricing & plans

This is the buyer-facing version of the editions contract. The implementation
source of truth is still the single feature table in
[`internal/license/license.go`](../internal/license/license.go); this page states
the public plan boundary and the metering units without inventing legal terms.

## Public price posture

| Plan | Price posture | Boundary |
|---|---|---|
| Core | **$0** for self-hosted core use | The full five-plane platform: observability, AI assistant and MCP, security/threat signals, topology, cost/SLO, OIDC SSO, SCIM, RBAC/ABAC, per-tenant export/deletion, fairness enforcement, and support-bundle generation. |
| Enterprise | **Flat-rate self-hosted license** | Every non-resale `ee/` capability: validated-module/FIPS distribution, BYOK, governance, guarded remediation, HA support/SLA, and siloed/hybrid isolation. |
| MSP | **Consumption-based self-hosted resale license** | The complete Enterprise set plus the provider plane and usage metering/export. The MSP resells under the probectl banner and sets its own customer prices. |

Enterprise is intentionally flat-rate because the customer bears the deployment
and telemetry infrastructure cost. MSP is intentionally consumption-based
because the operator resells a managed tenant service. `tenant_band` remains a
provisioning ceiling, not a telemetry kill switch. Contract rates and reseller
terms are counsel-owned artifacts; they do not create another runtime feature
table.

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
| Enterprise | `fips`, `byok`, `governance`, `remediation`, `ha_support` (displayed as HA support/SLA), `siloed_isolation` |
| MSP | Every Enterprise feature, plus `provider_plane` and `metering` |

MSP is a strict superset of Enterprise. Enterprise never grants
`provider_plane` or `metering`, because those are resale operations rather than
self-hosted product capabilities.

## Metering units

MSP metering is the probectl-to-MSP consumption basis and also feeds showback,
capacity planning, fairness reviews, and the MSP's own tenant billing. It is
collected locally from tenant-tagged streams already flowing through the
deployment.

The units are the same ones documented in [`metering.md`](metering.md):

| Meter | Kind | Unit | How to read it |
|---|---|---|---|
| `agents` | gauge | count | Peak number of registered agents in the period. |
| `tests` | gauge | count | Peak number of configured tests in the period. |
| `results_ingested` | counter | count | Sum of result records ingested in the period. |
| `ingest_bytes` | counter | bytes | Sum of result payload bytes ingested in the period; not retained-GB storage billing. |
| `flow_events` | counter | count | Sum of flow events or batches recorded in the period; not a hidden per-flow core gate. |
| `ai_calls` | counter | count | Sum of AI assistant questions in the period. |

This is an **operator-run export**: the operator explicitly downloads CSV or
JSON Lines from the provider plane.
probectl never uploads these values, calls a billing endpoint, or gains access to
tenant telemetry. The MSP chooses how those meters map to its customer pricing;
that downstream price is not configured by probectl.

Quotas use the creation-time controls from the Provider plane (`max_agents`,
`max_tests`). They do not drop telemetry: existing agents keep sending, ingest is
not silently discarded, and pooled fairness remains the layer that protects a
shared deployment under load.

## License and expiry behavior

Commercial activation is offline local math: the signed license file is verified
inside the control plane and never phones home. Unlicensed commercial surfaces are
hidden except for Admin -> Editions, and expired commercial features degrade
read-only after the grace period. Telemetry pipelines keep running.

The core license grant is already final: first-party source outside `ee/` is
covered by the unmodified MPL-2.0 text in the root [`LICENSE`](../LICENSE),
without Exhibit B. The draft `ee/LICENSE`, commercial agreements, reseller
terms, DPA/MSA, trademark posture, and open-data resale review remain
counsel-owned. This page describes product packaging and metering; it does not
replace that commercial paper.
