# ADR: agent config push stays unimplemented (de-documented) — U-044

**Status:** accepted (2026-06) · **Finding:** U-044 (O:ARCH-001) — StreamConfig
was a documented stub: docs implied a config-push capability the code does not
have.

## Decision

**De-document, don't implement.** The `StreamConfig` RPC stays in
`probectl.agent.v1.AgentService` as an explicitly-labeled unimplemented stub
(one empty epoch-0 frame, stream held open), and every place that described it
as a capability now describes it as a stub. Agents load configuration from
local YAML/env only.

## Why not implement push now

A remote config channel is a **remote control channel**. probectl's agent
security story leans on the absence of exactly that surface: no agent
self-update, no server-driven behavior change beyond scheduled probes
(strength ST-04; `docs/agent-security.md`). A careless push implementation
would hand a compromised control plane (or anyone who can impersonate it)
the ability to repoint probes, silence capture, or alter targets fleet-wide —
the threat model (`docs/threat-model.md`) calls the control plane's blast
radius out as the top asset. Config push is only acceptable as a **signed,
verifiable** design: payloads signed by an offline key the control plane does
not hold, epoch-monotonic, agent-side verification before apply, full audit.
That is its own future task with its own ADR + threat-model delta — not a
side effect of closing a doc gap.

## What changed (all comments/docs, zero wire change)

- `proto/probectl/agent/v1/agent.proto` — rpc + payload comments say
  UNIMPLEMENTED STUB / RESERVED, pointing here.
- `internal/agenttransport/service.go` + `doc.go` — same wording; the S7+
  "real config arrives later" promise is gone.
- `docs/architecture.md` — the RPC list marks StreamConfig as a stub.

The RPC itself is kept (removal is a buf-breaking change and the stub costs
nothing); `Heartbeat.config_stale` likewise remains a no-op field until a
signed design lands.

## Addendum — Sprint 13 hardening (ARCH-003, blind second audit)

The blind audit read the held-open stub as remote-config attack surface
(ARCH-003). The triage verdict: the concern was overstated — the agent has no
config-apply path at all — but the stub's behavior (send an empty epoch-0
frame, hold the stream open) was pointless surface for a non-capability. The
decision above STANDS unchanged; within it, the server now answers
StreamConfig with an immediate, explicit `codes.Unimplemented` citing this
ADR: no frame is ever sent, no stream is ever held, and a test fails the
build if a frame sneaks back (`TestStreamConfigExplicitDeny`). A second
static test asserts the agent binary contains no client invocation. The RPC
remains in the schema — zero wire change, buf-breaking stays green — so the
de-document-don't-implement posture is now also enforce-don't-serve.

## Revisit when

A customer-driven need for centrally-pushed probe definitions, or fleet scale
making local config distribution impractical — then: signed-push ADR first,
threat-model update, then implementation behind its own tier/flag.
