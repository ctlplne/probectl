# ADR: A2A measurements are broker-coordinated, not scheduled plugins

**Status:** Accepted — 2026-07-14

## The plain version

An ordinary canary is one agent doing one job on a timer: “from here, probe
that DNS server every 60 seconds.” An agent-to-agent (A2A) measurement is a
three-step handshake between two registered agents:

1. tell one agent to open a short-lived responder listener;
2. authenticate and report that listener's endpoint to the control plane;
3. tell the other agent to initiate the measurement against that endpoint.

That handshake needs one tenant-scoped coordinator with a view of both agent
identities. Therefore A2A is deliberately **not** registered in the agent's
scheduled `Canary` plugin registry. The control-plane broker creates pair or
mesh sessions, and each opted-in agent's `Coordinator` polls for its role.

## Decision

A2A scheduling is owned by the control-plane broker in `internal/a2a` and is
started through the tenant/RBAC-scoped, audited surfaces:

- `POST /v1/a2a/sessions` / `probectl a2a create-session` for one directed
  pair; and
- `POST /v1/a2a/mesh` / `probectl a2a start-mesh` for every directed pair in
  a site-labeled mesh.

`a2a.enabled: true` in agent configuration means **this agent may
participate**. It starts the coordination poller; it does not create a local
interval schedule. An `a2a` entry under `canaries:` is unsupported and fails
registry construction because no such scheduled plugin is registered.

The two execution paths remain deliberately separate:

| Path | Who schedules it | Unit of work | Agent runtime |
|---|---|---|---|
| Agent-to-service canary | local `canaries[]` interval | one agent + one configured target | `Host` + compiled-in `Canary` registry |
| Agent-to-agent measurement | tenant-scoped control-plane broker | responder + initiator + one session | `Coordinator` polling `PollCoordination` |

Both paths produce the same tenant/agent-stamped result envelope and use the
same disk-backed store-and-forward buffer. The difference is only how a safe,
executable assignment is formed.

## Why a normal scheduled plugin is the wrong shape

The scheduled plugin interface receives one local target and interval. It
cannot safely answer the questions A2A must answer together: which two
currently registered agents belong to this tenant, which role each has, where
the responder actually bound its ephemeral port, and which fresh session key
authenticates the probe frames.

Registering `a2a` as an ordinary plugin would create two competing schedulers
and invite races: an initiator could run before its responder exists, use a
stale endpoint, or select a peer without the tenant/RBAC/audit checks at the
session API. Duplicating the same pair in two agents' local YAML would also
make role ownership ambiguous. The broker makes the ordering explicit and
keeps one authority for each session.

## Boundary and failure behavior

- The session API derives tenant identity from the authenticated caller before
  applying RBAC; the request body cannot choose a tenant.
- Agents receive tasks for only their `(tenant, agent)` key, derived from their
  verified mTLS identity. Only the assigned responder can report an endpoint.
- The random session id is delivered over mTLS and derives the HMAC key used to
  authenticate A2A request/reply frames through `internal/crypto`.
- A2A is off by default, so an agent opens no responder listener until the
  operator enables participation and the broker assigns a responder task.
- Lost probes become explicit unsuccessful results, invalid frames are ignored,
  and setup/dial failures are logged; none of those paths can become invented
  success data.

The current broker and mesh-session state are in process and short-lived. A
control-plane restart can expire an outstanding session, which the operator
may submit again. This ADR fixes scheduling ownership; it does not claim that
ephemeral coordination state is a durable system of record.

## Alternatives rejected

1. **Register A2A as a local canary.** Rejected because a one-agent timer cannot
   securely sequence a two-agent rendezvous.
2. **Put matching schedules in both agents' YAML.** Rejected because there is
   no single role, endpoint, tenant-policy, or audit authority.
3. **Push A2A schedules through remote agent configuration.** Rejected because
   config push is intentionally unimplemented; see
   [the config-push ADR](config-push.md). A transient, scoped task is smaller
   and safer than a fleet-wide remote configuration channel.

## Revisit when

Revisit only if the canary contract grows a first-class multi-agent task model.
Any replacement must preserve tenant-first selection, RBAC, audit, responder
authorization, fresh session authentication, and explicit operator opt-in. A
second independent scheduler is not an acceptable migration path.
