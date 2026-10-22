# ADR: central test distribution — agents pull a signed test bundle

**Status:** accepted (2026-10-21, decision D-41 / PD-1; closes PLAT-13).
Supersedes [`config-push.md`](config-push.md) for synthetic test definitions
only; `StreamConfig` stays an explicit deny and no other agent setting can be
changed remotely.

## The plain version

A test someone creates in the console, the API or the CLI has to reach the
agents that run it. Until now it never did: agents ran only the tests in their
own local YAML, so a new user's first test sat there forever. Now each agent
asks the control plane, over the mTLS connection it already has, "which tests
does my tenant run?", checks the answer's signature, and runs it. The control
plane never pushes; the agent pulls, verifies, and can always refuse.

## Decision

- **Transport:** a `FetchTestBundle` call on the existing agent gRPC service
  (`proto/probectl/agent/v1/agent.proto`). No new listener, port, protocol or
  certificate. The agent's tenant comes from its client certificate
  (docs/guardrails.md G7-4), never from the request; the request carries only
  the version the agent already runs.
- **Source:** `internal/testsync.Source` reads the tenant's enabled tests under
  the tenant's RLS scope (docs/guardrails.md G7-1) and signs them. A tenant
  sees only its own tests at the storage layer, whatever the handler does.
- **Signature:** the control plane signs each bundle with a dedicated Ed25519
  key (`PROBECTL_TESTSYNC_SIGNING_KEY_FILE`), separate from every TLS and CA
  key, through `internal/crypto` (G7-3). The agent verifies with
  `testsync.Verify` against the deployment's public key, which it receives at
  enrollment over the token-authenticated, CA-verified enrollment exchange (and
  again at every possession-proven identity rotation, which is how agents
  enrolled earlier get it) and stores beside its certificate as `testsync.pub`
  (`probectl-control testsync public-key` prints it for agents provisioned by
  hand). Every replica of a deployment loads the same key.
- **Replay:** each bundle's epoch is the tenant's test-set version
  (`tenant_test_set_versions`, migration 0125), a counter bumped in the same
  transaction as every test create, update and delete. It only increases and
  needs no clock shared between replicas. The agent refuses a bundle whose
  version is not newer than the one it runs, and refuses a bundle naming
  another tenant than its certificate's.
- **Fail closed:** an unverifiable, stale or foreign bundle is refused and
  counted (`probectl_agent_testsync_refused_total{reason}`); the agent keeps
  running its last verified set (persisted 0600, and re-verified at start) and
  its local tests. No key means no central tests. No signing key on the control
  plane means the pull answers `FailedPrecondition`.
- **Nudge:** the heartbeat reports the version the agent holds
  (`config_epoch`); the reply sets the existing `config_stale` flag when the
  tenant's set changed, and the agent fetches at once instead of waiting for
  its poll interval. The reported version is recorded per agent, so
  `GET /v1/agents` says whether each agent runs the tenant's current tests.
- **Audit:** creating, changing or deleting a test is already audited on the
  tenant's chain.

## What a compromised control plane can still do, and the bound on it

The old ADR asked for a signing key the control plane does not hold, so that a
compromised control plane could not forge configuration. That property cannot
coexist with "a test created in the console runs": something online must sign
what a user just created. This design accepts that, and bounds the blast radius
on the agent instead, where the control plane cannot reach:

- central tests can use only the canary types the agent has compiled in and
  its operator allows (`test_sync.allowed_types`);
- they may not probe private, loopback or link-local targets unless the
  agent's own configuration allows it (`test_sync.allow_private_targets`,
  default false), the same SSRF guard local tests have. Shipped agent configs
  turn it on only for single-tenant (sovereign) installs, where the operator
  owns both ends: the evaluation canaries, and the `test_sync:` block the
  First-run setup page hands out when the deployment profile is `single`.
  MSP-hosted (`multi-tenant`/`regulated`) agent configs keep false, because
  there this guard is what stops the hosted control plane from making a
  customer's agent probe that customer's internal network (decision D-57; the
  control plane never overrides the agent's value);
- interval and count floors cap the probe rate a bundle can request
  (`test_sync.min_interval`, `test_sync.max_tests`);
- central tests carry no code, no commands and no agent setting: only the
  fields of `testsync.Test`.

A compromised control plane can therefore make agents probe public targets
within those limits, which it could already affect by other means, and
nothing more. The signature still protects every hop and copy the control
plane does not own: the persisted bundle on the agent's disk, and any proxy or
relay between them.

## Revisit when

A partner needs per-agent assignment (labels or selectors), or wants bundles
co-signed by a key held outside the control plane for a regulated estate.
