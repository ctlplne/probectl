# Running probectl in production

## What it is

This page covers the work of keeping a probectl deployment alive and healthy over
its whole life: upgrading it without taking it offline, rolling a new agent
version across a fleet a slice at a time, running it in a hardened cryptographic
mode for regulated environments, surviving the loss of a whole region, governing
how long data lives and how it is masked or deleted, and handing a diagnostician
a single file that explains a problem without leaking a single secret.

Think of it as the difference between *building* a car and *operating a fleet of
them*: the engine is the same, but now you care about oil changes you can do
without stopping the car, swapping a part across the whole fleet in waves,
running on certified fuel, and a black-box recorder that captures the instruments
but never the passengers' conversations.

Five capabilities live here:

- **Zero-downtime lifecycle** — upgrade and roll back at every step, with no outage.
- **Fleet rollout** — promote a new agent version ring by ring, watching health.
- **Hardened cryptographic mode** — a build that operates a government-validated
  cryptographic module (the Federal Information Processing Standards mode, FIPS).
- **Multi-region high availability (HA)** — survive a region failure with no data
  corruption.
- **Governance and supportability** — control data retention, masking, erasure,
  and per-customer keys; produce a secret-free support bundle on demand.

Terms of art ([glossary](../glossary.md)) such as TLS, mTLS, RLS, BYOK, FIPS, and
KEK are defined there.

## Why it exists

A monitoring platform is itself a service somebody has to operate at 3 a.m. The
worst time to discover your observability tool needs a maintenance window is the
moment you most need to watch the network. So probectl is built so that the boring
operational tasks — upgrades, failovers, key rotations — happen *without* a gap
in observability.

Each capability answers a concrete fear:

- **"Will the upgrade take us down?"** No. The control plane runs as
  interchangeable copies (replicas) behind a traffic distributor (a load
  balancer), and you replace them one at a time while the rest keep serving.
- **"Will a bad agent release break the whole fleet at once?"** No. A new agent
  version reaches a small canary slice first, so a regression hurts a few percent,
  not everyone.
- **"Can we satisfy a regulator who demands a validated crypto module?"** Yes —
  there is a build that operates one.
- **"What happens if a region dies?"** The control plane keeps serving reads and
  ingest everywhere; the database fails *closed* on writes during the flip so it
  can never corrupt state.
- **"Can we honour a deletion or residency obligation, and prove it?"** Yes —
  erasure produces a proof document anyone can re-derive.
- **"Can we get a diagnostic file to support without leaking credentials?"** Yes —
  the support bundle is structurally secret-free.

## How it works

### Zero-downtime upgrades (the one rule)

During a rolling upgrade the old release and the new release run *side by side*,
so everything they share — the database schema, the agent protocol — must work
for both at once. It is like resurfacing a bridge one lane at a time: traffic
keeps flowing in both lanes, so every intermediate state must carry both.

Two mechanisms make that safe:

- **The control plane holds no durable state of its own.** All state lives in the
  databases, so any replica can serve any request and killing one loses nothing.
  On a polite shutdown signal a replica immediately reports *not ready* to the
  load balancer (so new traffic stops), finishes the requests it already accepted,
  then exits. A replacement starts serving only once it reports *ready*.
- **Schema changes are additive (expand, then contract).** A destructive change
  is never done in one step. First you *expand*: add the new column or table,
  backfill it, write both shapes. Later, once nothing reads the old shape, a
  separate release *contracts*: drops the old one. A standing check rejects any
  migration that would break the previous release mid-upgrade — drops, renames,
  type changes, or adding a non-null column with no default. Because the schema
  only ever *added*, rollback is trivial: the previous release still works against
  it.

### Agent version skew and staged rollout

The control plane is the authority on whether an agent is compatible. It accepts
an agent within a one-version window in *both* directions — an older agent
talking to a newer control plane works, and vice versa — so a fleet can run a mix
during a rollout. An agent too far behind is rejected with a clear "upgrade
required" message, distinct from a transient error, so it surfaces to an operator
instead of looping forever.

You promote a new agent version *ring by ring*. Each agent lands in a stable
cohort by a hash of its identity (stable so it never flaps between rings): a small
**canary** ring first, then **early**, then the **main** fleet. You advance one
ring at a time, watching health between rings.

### Hardened cryptographic (FIPS) mode

Every cryptographic operation in probectl flows through one internal choke point,
and a build-time guard blocks any other code from calling a crypto primitive
directly. That single choke point is what makes a validated-module build possible:
a FIPS 140-3 validated cryptographic module is compiled in transparently, swapping
the implementation underneath while every output stays byte-for-byte identical.

The honest, auditable claim: the FIPS build operates the FIPS 140-3 *validated Go
Cryptographic Module* (you verify its certificate number with the validating body
yourself). probectl as a product does not hold its own module certificate — the
*module* does. Both the control plane and the agent run a power-on self-test
before serving any traffic and **fail closed** (refuse to start) if it errors, and
in the FIPS build the self-test also asserts the validated module is actually
active.

### Multi-region high availability

probectl runs **active-active** across regions for the parts that can: every
region runs stateless control-plane and ingest replicas, all serving at once.
Durable state is a single-writer database with streaming read replicas in the
other regions. There is exactly one writable primary at any instant.

The safety core is **split-brain fencing**. "Split-brain" is the nightmare where
two nodes both believe they are the primary and both accept writes, silently
diverging. probectl refuses to write unless the target is *provably* the current
primary: it probes the writer endpoint every few seconds and **fails writes
closed** (returning a retry-after) whenever it cannot prove that — while reads
keep serving and telemetry ingest never pauses. A monotonic promotion counter
catches a stale ex-primary; a lower counter can never reclaim the writer role.
The principle: degrade to read-only, never lose or corrupt data.

Be precise about one asymmetry: the durable state database carries over with a
seconds-scale recovery point. The high-volume telemetry store does **not**
replicate cross-region by default — its regional recovery point equals your
off-region backup cadence unless you opt into telemetry-store replication
yourself. Record both numbers in your disaster-recovery plan so the gap is visible
to whoever is on call.

### Governance: retention, masking, erasure, residency, keys

Governance is one coherent view per customer over five concerns:

- **Classification.** Every sensitive data category gets a sensitivity class. The
  headline: an IP address defaults to personally identifiable information (PII),
  because under privacy law an IP address *is* personal data.
- **Redaction.** When masking is active, every category at or above a configurable
  floor (PII by default) is masked. The default strategy keeps a coarse,
  non-identifying prefix — "blur the house number, keep the street" — so analytics
  still group by network while no value points at one host. Credentials always
  drop entirely. Masking is best-effort pseudonymisation, **not** anonymisation:
  for irreversible removal, use erasure.
- **Retention.** Each store has its own deletion clock; you set how long flow,
  path, host-level, and trace/log telemetry live.
- **Erasure.** Customer-erase and subject-erase are the wide brooms: they remove
  or project data across every *live* store and produce a recomputable
  attestation — a proof anyone can re-derive to confirm the deletion happened.
  Backups keep their own clock; a governed deletion records your backup-retention
  deadline rather than reaching into a backup.
- **Per-customer keys / BYOK.** On the licensed tier, each customer's sensitive
  at-rest values can be sealed under that customer's own key, so offboarding
  becomes a key-destruction event. An unavailable or destroyed key is an error,
  never a silent fallback to a shared key.

### Supportability

A support bundle is a single archive of diagnostic files — version, redacted
config, deep-health report, self-metrics, an anonymized topology summary, and a
runtime snapshot. **The non-negotiable property: it never contains secrets,
credentials, or PII**, kept true by three independent layers: the config snapshot
is built from an *allowlist* of known-non-secret keys (so a secret added in a
later release cannot leak, because it simply is not on the list), the topology
file is counts only, and a final scrub replaces this deployment's actual secret
values anywhere in the bytes.

## Use it

**Roll the control plane.** Apply migrations first (they are additive, safe for
the still-running release), then replace replicas one at a time. Health and
readiness are separate on purpose:

```sh
# liveness: is the process alive at all?
curl https://control.example/healthz
# readiness: should the load balancer send it traffic right now?
curl https://control.example/readyz
```

What you should observe: during a graceful shutdown, `/healthz` stays `200`
(the process is still serving what it accepted) while `/readyz` flips to `503`
(draining — stop sending new traffic). The replacement serves only once `/readyz`
returns `200`.

**Build and verify the hardened crypto mode.** A status field reports the live
posture (build tag, module active, enforced, self-test passed):

```json
{
  "fips": {
    "build_tag": true,
    "module_active": true,
    "enforced": false,
    "self_test_passed": true
  }
}
```

What you should observe: `self_test_passed: true` means the power-on self-test
ran and the validated module is live. If the self-test had failed, the process
would not have started at all.

**Watch the cluster during a failover.** The readiness endpoint carries the
cluster view; a node stays ready for *reads* while writes pause:

```json
{
  "status": "ready",
  "cluster": { "topology": { "region": "eu" }, "writer": { "role": "reader" }, "writes_usable": false }
}
```

What you should observe: `writes_usable: false` tells operators and automation
that writes paused (fenced) during the flip; reads and ingest keep flowing.
Writes resume automatically on the next probe once the writer endpoint resolves
to the promoted primary — no restart needed.

**Produce a support bundle.** Either live from the API or offline straight from
the binary with no running server:

```sh
probectl-control support-bundle -o /tmp/probectl-support.tar.gz
```

What you should observe: a gzipped archive of JSON files. Database URLs have their
passwords stripped; the encryption key shows up only as a boolean
`envelope_key_configured`, never the key itself.

**Take a governed, masked export of a customer's data:**

```sh
curl 'https://control.example/v1/lifecycle/export?redact=true' -o tenant-export.tar.gz
```

What you should observe: the export manifest carries `"redacted": true`; IP
addresses appear as a coarse prefix (for example `203.0.113.0/24`), emails as
`a***@domain`, and credentials are gone entirely, while counts and protocol names
survive.

## Pitfalls & limits

- **The telemetry store does not replicate cross-region by default.** The durable
  state database recovers in seconds; the high-volume telemetry store recovers to
  your last off-region backup unless you run telemetry-store replication yourself.
  This is a deliberate trade — replicating high-cardinality telemetry globally is
  expensive and often residency-restricted — but never paper over it: record the
  telemetry recovery point next to the state recovery point.
- **Recovery-point and recovery-time targets are provisional until you validate
  them.** The shipped numbers are engineering estimates; they become committed
  numbers only once your own failover drills back them on real infrastructure.
- **The hardened crypto mode is a build, not a runtime toggle to a feature.** The
  binary you run *is* the gate — there is no license switch that turns FIPS on. It
  is a hardening posture, not a feature surface.
- **Some at-rest encryption is the operator's job, by design.** probectl seals
  sensitive *values* itself, but it does not re-encrypt the bulk telemetry stores'
  data files at scale — that is your storage layer's responsibility (encrypted
  volumes). A bundled preflight check reports which of your data paths are
  detectably encrypted so this duty is never silently skipped.
- **Lose the encryption key and sealed values become unreadable.** Back up the
  key material like you back up the data. A keyless production startup is a fatal
  error, never a silent fallthrough to plaintext.
- **Masking is not anonymisation.** The default strategy keeps a network prefix
  and the hash strategy is correlatable. You cannot promise a masked value
  identifies nobody. For that, erase.
- **Erasure clears live stores, not backups.** A governed deletion attests the
  live-store removal and records your backup-erasure deadline; the backup
  destination owns its own clock.
- **The live cross-region disaster-recovery exercise is yours to run.** The
  runbook and an automated drill exist, but the real exercise needs real
  infrastructure and is an operator action.

## Reference

- **Upgrade:** apply additive migrations first, then replace control-plane
  replicas one at a time; roll back by replacing them with the prior release.
- **Health probes:** `GET /healthz` (liveness), `GET /readyz` (readiness, carrying
  the cluster view: region, writer role, `writes_usable`, replica lag). Deep
  per-component health is at `GET /v1/diagnostics` (admin only); the aggregate
  equals the worst component.
- **Agent rollout:** one-version compatibility window in both directions; staged
  cohorts (canary → early → main), advanced one ring at a time.
- **Hardened crypto posture:** reported under `fips` on `GET /v1/editions`
  (`build_tag`, `module_active`, `enforced`, `self_test_passed`); a power-on
  self-test gates startup and fails closed.
- **Multi-region:** active-active stateless control plane; single-writer database
  with streaming replicas; write fencing during failover; telemetry-store
  cross-region replication is an operator opt-in, not a built-in.
- **Governance:** masked export via `GET /v1/lifecycle/export?redact=true`;
  subject export/erase via `POST /v1/lifecycle/subjects/export` and
  `POST /v1/lifecycle/subjects/erase`; erasure produces a recomputable
  attestation; per-customer keys / BYOK on the licensed tier.
- **Support:** `GET /v1/diagnostics/bundle` (live, admin only) or
  `probectl-control support-bundle` (offline); the bundle is structurally
  secret-free.
- **Related capabilities (separate pages):** Tenancy & isolation; the Provider /
  MSP plane (break-glass, metering, white-label, residency, per-tenant keys).

**Covers:** F28, F32, F33, F34, F35
