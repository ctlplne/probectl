# Remote-AI egress: what leaves the network, and the three gates (U-013)

probectl's default AI engine is **air-gapped** (the deterministic builtin; a
loopback Ollama/vLLM is equally local). Configuring a **remote** model
endpoint (`openai` / `anthropic`, or `ollama` pointed at a non-loopback host)
changes the sovereignty story: per RCA question, data leaves the operator's
network. This page is the disclosure — it is written to be attached to a DPA.

## Exactly what is sent, per remote call

One HTTPS POST to the configured endpoint containing:

- the user's **question text**, verbatim¹;
- per evidence item (max `PROBECTL_AI_MAX_EVIDENCE`, default 50): its ID,
  **plane** (network/bgp/flow/device/ebpf/incident…), **severity**,
  **title**, **summary**, and timestamp¹;
- the system prompt (static probectl text) and model name.

Never sent: credentials/tokens (the API key authenticates the call itself and
is stored as an S41 secret reference), raw telemetry rows, packet payloads,
database contents, or anything outside the caller's tenant + RBAC scope (the
evidence is gathered tenant-first through the S23 engine).

¹ After the C8 redaction pass (`docs/ai-egress.md` consumers: see
`internal/ai/redact.go`): IPs and obvious secrets are masked, hostnames per
policy, before the prompt leaves.

**Processing by the model provider is governed by YOUR agreement with that
provider** — probectl sets no retention terms on the remote side. DPA inputs:
processor = the model provider; data categories = the list above; transfer
trigger = each `/v1/ai/*` query by a consenting tenant; safeguards = TLS
(hardened client), redaction pass, per-tenant consent, audit trail.

## The three gates

1. **Operator acknowledgment (boot-time, fail-closed).** A remote endpoint
   refuses to start until the operator sets
   `PROBECTL_AI_EGRESS_ACK=yes-send-tenant-data-to-the-remote-model` —
   the off-network flow must be a deliberate decision, never a default.
2. **Per-tenant consent (call-time, default deny).**
   `tenant_governance.ai_remote_egress` (provider governance API/console)
   defaults to **false**; the analyzer refuses remote synthesis for a
   non-consenting tenant (`ErrEgressDenied`). The builtin/loopback path is
   exempt and keeps working for everyone.
3. **Audit (every call).** Each remote call appends `ai.remote_egress` to the
   tenant's tamper-evident audit stream: endpoint, model, evidence count and
   the **data categories (planes)** that left — never the content itself.

## Turning it on

```sh
PROBECTL_AI_MODEL_PROVIDER=anthropic
PROBECTL_AI_MODEL_ENDPOINT=https://api.anthropic.com
PROBECTL_AI_MODEL_TOKEN=vault:ai/anthropic#key
PROBECTL_AI_EGRESS_ACK=yes-send-tenant-data-to-the-remote-model
# then, per tenant that may use it:
# PUT /provider/v1/tenants/{id}/governance  {"ai_remote_egress": true, ...}
```
