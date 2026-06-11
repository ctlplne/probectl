# ADR: agent config push stays unimplemented (de-documented)

**Status:** accepted (2026-06)

**Context:** `StreamConfig` was a *documented stub* — a stub is a declared
call with no real behavior behind it, and the docs implied a config-push
capability that the code does not actually have. This ADR — an architecture
decision record, a dated note capturing a decision and its why, kept even
after the code moves on — records the decision to keep it that way, and why.

## The plain version

There are two ways an agent can learn its configuration. **Pull/local**: the
agent reads a file on its own host. **Push**: the agent asks the control
plane "what should I be doing?" and the server streams down a new
configuration — new probe targets, new schedules. probectl deliberately does
**not** do push. Agents read their configuration from local YAML/env on their
own host, full stop. This ADR is the decision to leave that door closed and to
make the codebase say so honestly instead of hinting at a feature that isn't
there.

## Decision

**De-document, don't implement.** The `StreamConfig` RPC (remote procedure
call — a function one machine exposes for another to invoke) stays in
`probectl.agent.v1.AgentService` (`proto/probectl/agent/v1/agent.proto`) as an
explicitly-labeled unimplemented stub, and every place that once described it
as a capability now describes it as a stub. Agents load configuration from
local YAML/env only.

## Why not implement push now

Intuition first: **a remote config channel is a remote control channel** — a
universal remote for every screen in the building. Whoever holds it, or
counterfeits it, changes every screen at once; the only remote that cannot be
stolen is the one that was never manufactured. If the control plane can tell
an agent "probe this target on that schedule," then anyone who can
*impersonate* the control plane can repoint probes, silence packet capture, or
change targets across the whole fleet at once. probectl's agent security story
leans on the *absence* of exactly that surface — there is no agent self-update
and no server-driven behavior change beyond the scheduled probes the agent
already runs locally (see the "no self-update channel" section of
`docs/security/agent-whitepaper.md`).

The depth: the system-wide threat model (`docs/security/threat-model.md`)
names the control plane's blast radius as the top asset to protect. A careless
push implementation hands a compromised — or merely impersonated — control
plane fleet-wide reach. Config push is therefore only acceptable as a
**signed, verifiable** design:

- payloads signed by an offline key the control plane does **not** hold (so a
  compromised control plane cannot forge a config);
- epoch-monotonic — each config carries a counter that only increases, so an
  old config can't be replayed over a newer one;
- agent-side verification *before* apply (the agent refuses anything it can't
  verify — fail closed);
- fully audited.

That is its own future task with its own ADR and its own threat-model delta —
not a side effect of closing a documentation gap.

## What changed (all comments/docs, zero wire change)

- `proto/probectl/agent/v1/agent.proto` — the rpc and payload comments mark
  `StreamConfig` and the `StreamConfigResponse` payload as an UNIMPLEMENTED
  STUB, pointing here.
- `internal/agenttransport/service.go` + `doc.go` — same wording; the old
  "real config arrives later" promise is gone.
- `docs/architecture.md` — the RPC list marks `StreamConfig` as an explicit
  deny.

The RPC itself is kept because removing it from the schema is a buf-breaking
change (buf is the schema linter for Protobuf, the binary message format
agents and the control plane share; "breaking" means already-deployed agents
would no longer match the wire contract) and the stub costs nothing.
`Heartbeat.config_stale` likewise remains a no-op field until a signed design
lands.

## Hardening: enforce, don't merely document

A later security review read the original stub — which sent an empty epoch-0
frame and then held the stream open — as remote-config attack surface. The
triage verdict: the concern was overstated (the agent has no config-apply path
at all), but holding a stream open for a non-capability was pointless surface.

The decision above stands unchanged. Within it, the server now answers
`StreamConfig` with an immediate, explicit `codes.Unimplemented` — the gRPC
status that tells a caller "this method exists in the schema but has no server
behavior" — citing this ADR (`internal/agenttransport/service.go`): **no frame
is ever sent, no stream is ever held open.** Two tests lock this in:

- `TestStreamConfigExplicitDeny` — fails the build if a frame ever sneaks back
  onto the wire.
- `TestAgentHasNoStreamConfigInvocation` — a static scan of the agent runtime
  and binary sources asserting they contain no client-side call to
  `StreamConfig` at all (the generated client stub exists by design — the
  schema keeps the RPC; nothing invokes it).

The RPC remains in the schema (zero wire change, buf-breaking stays green), so
the "de-document, don't implement" posture is now also "enforce, don't serve."

## Revisit when

A customer-driven need for centrally-pushed probe definitions, or fleet scale
that makes local config distribution impractical — then, in order: a
signed-push ADR, a threat-model update, and only then an implementation behind
its own tier/flag.
