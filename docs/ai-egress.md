# Remote-AI egress: what leaves the network, and the three gates

## What this page is

probectl's default AI is **air-gapped**: the deterministic builtin synthesizer, and
a loopback Ollama/vLLM, both run entirely on your own hardware and send nothing
out. The moment you configure a **remote** model endpoint — `openai`, `anthropic`,
or an `ollama` pointed at a non-loopback host — the sovereignty story changes: to
answer a question, some data leaves your network.

This page is the **disclosure** of exactly what leaves, and the three independent
controls that stand in front of it. It's written to be attached to a Data
Processing Agreement (DPA): if you connect a cloud model, this is the document your
privacy/legal review reads.

## Exactly what is sent, per remote call

One HTTPS POST to the endpoint you configured, containing:

- the user's **question text**, verbatim¹;
- per evidence item (at most `PROBECTL_AI_MAX_EVIDENCE`, default **50**): its **ID**,
  **plane** (network / bgp / flow / device / ebpf / incident / …), **severity**,
  **title**, **summary**, and **timestamp**¹;
- the **system prompt** (static probectl text instructing the model to use only the
  evidence and cite it) and the **model name**.

**Never sent:** API keys or tokens (the API key authenticates the call itself; it
is supplied as a secret reference — see `docs/secrets.md` — not embedded in any
payload), raw telemetry rows, packet payloads, database contents, or anything
outside the caller's tenant + RBAC scope. The evidence is gathered **tenant-first**
through the semantic query engine (`docs/ai-query.md`) before a model ever sees it,
so off-scope data can't be in the prompt to begin with.

¹ **After the redaction pass** (`internal/ai/redact.go`): secrets are **always**
masked; IP addresses and free-text PII (emails, phone numbers, MAC addresses) are
masked **by default**; hostnames and any operator-supplied custom patterns
(`PROBECTL_AI_REDACT_PATTERNS`, `;;`-separated regexes) are masked **per policy** —
all before anything leaves. Masking is *deterministic per value*: the same IP
becomes the same token every time, so the model can still correlate ("this address
appears in both signals") without ever seeing the real value.

## One gate, three doors

The same `EgressGate` (`internal/ai/egressgate.go`) — consent + redaction + audit,
**one instance constructed once** in the control plane — guards every path that
sends tenant data to an external AI:

- the **remote RCA model** (`docs/ai-rca.md`),
- **MCP tool results** (an MCP caller *is* an external AI client; `docs/mcp.md`),
- the **test-authoring model** (`docs/ai-authoring.md`).

The audit event records which door it came through: `surface = rca | mcp | author`.
There is deliberately no second construction site and no gate-less path — a static
test (`TestNoAIClientOutsideGate`, `internal/ai/egressgate_test.go`) scans the
source tree and fails the build if any file outside the single approved adapter
gains the ability to dial out. So a future surface *cannot* quietly route around
the gate.

**Who governs the data once it leaves:** your agreement with the model provider.
probectl sets no retention terms on the remote side. DPA inputs, ready to copy:
processor = the model provider; data categories = the list above; transfer trigger
= each `/v1/ai/*` query by a consenting tenant; safeguards = TLS (hardened,
cert-validating client), the redaction pass, per-tenant consent, and a per-call
audit trail.

## The three gates

All three must be satisfied. Each is independent, and each fails closed.

1. **Operator acknowledgment (boot-time, fail-closed).** A remote endpoint refuses
   to start until the operator sets, exactly:

   ```
   PROBECTL_AI_EGRESS_ACK=yes-send-tenant-data-to-the-remote-model
   ```

   Config validation rejects a remote `PROBECTL_AI_MODEL_ENDPOINT` without this
   phrase. Sending data off-network must be a deliberate operator decision, never a
   default that happens because someone filled in an endpoint.

2. **Per-tenant consent (call-time, default deny).** Even with the operator's ack,
   each *tenant* must opt in. `tenant_governance.ai_remote_egress` (migration
   `0037_governance_ai_egress.sql`) defaults to **false**; the analyzer refuses
   remote synthesis for a non-consenting tenant with `ErrEgressDenied`. No
   consent row, no database, or any read error all resolve to "denied" — fail
   closed, never fail open. The builtin and loopback-local paths are **exempt** and
   keep working for everyone, because they don't egress anything.

3. **Audit (every call).** Each allowed remote call appends `ai.remote_egress` to
   the tenant's tamper-evident audit stream: the endpoint, the model, the evidence
   count, and the **data categories (planes)** that left — never the content
   itself. (On the MCP surface there's also an `mcp.tool_call` audit line per call,
   recording allow/deny and the reason.)

## Turning it on

```sh
# 1. operator acknowledgment (boot-time)
PROBECTL_AI_MODEL_PROVIDER=anthropic
PROBECTL_AI_MODEL_ENDPOINT=https://api.anthropic.com
PROBECTL_AI_MODEL_TOKEN=vault:ai/anthropic#key   # a secret reference (docs/secrets.md)
PROBECTL_AI_EGRESS_ACK=yes-send-tenant-data-to-the-remote-model

# 2. then, per tenant that may use it, via the provider/MSP governance console:
#    PUT /provider/v1/tenants/{id}/governance  {"ai_remote_egress": true, ...}
```

The per-tenant consent toggle lives on the **provider/management plane** (the
governance route is part of the commercial provider console). In a single-tenant
deployment that's just the one tenant; in a multi-tenant/MSP deployment each tenant
is consented individually.

## Remote-provider resilience

A slow or down provider must degrade RCA gracefully — never take it down. When a
model is configured, its call path is wrapped by `ResilientModel`
(`internal/ai/model_resilient.go`), which adds:

- **a circuit breaker** (`internal/breaker`): **3** consecutive failures open the
  circuit for **30s**, so calls short-circuit instead of stacking up timeouts
  against a dead provider;
- **a timeout**: the configured model timeout (`PROBECTL_AI_MODEL_TIMEOUT`) is
  enforced at the wrapper via context deadline, regardless of the HTTP client's own
  settings;
- **a response cache**: an identical question + evidence within **10 minutes** is
  answered without a provider round-trip (up to 256 entries). Because evidence IDs
  are per-session random, the cache keys on **content**, and cached citations are
  remapped onto the current run's IDs — so citation grounding still validates them;
- **graceful degradation**: on breaker-open / timeout / error, the **air-gapped
  builtin** answers instead. The answer is clearly marked — it carries
  `degraded: true` and the root cause is prefixed `PARTIAL RESULT — remote model
  unavailable (…)`, with the builtin's own grounded citations. An answer always
  comes back; it never silently fails.

The consent gate is unchanged by any of this: a remote-*configured* deployment
requires tenant consent before any synthesis — **including cache hits and fallback
answers**. The strict reading is that the *configuration* (not the individual
network packet) is the consent subject, so even a cached or degraded answer in a
remote-configured deployment is gated. The builtin default path is never wrapped —
there's nothing to break.

## What it deliberately does not do

- **It does not turn egress on for you.** Three explicit decisions (operator ack +
  per-tenant consent, with audit) stand between "endpoint configured" and "data
  leaves."
- **It does not send raw telemetry, secrets, or off-scope data.** Evidence is
  scoped, reduced to a small set of display fields, and redacted before egress.
- **It does not assume the cloud.** The default and the recommended sovereign path
  are fully local; everything here applies *only* once you opt into a remote model.

## See also

- `docs/ai-rca.md` — the RCA pipeline the remote model plugs into.
- `docs/mcp.md` — the MCP surface, which rides this same gate.
- `docs/ai-authoring.md` — the authoring model, also gated here.
- `docs/secrets.md` — secret references for the model token.
- `docs/configuration.md` — every `PROBECTL_AI_*` key.
