# Staged fleet rollout

## What this is

How a fleet of probectl agents moves to a new version: in **waves**, from
**verified, digest-pinned** artifacts, with the agent registry **confirming**
every wave, and any failure **halting the train**. The goal is that a bad
version reaches a small canary first and stops there, instead of taking out
the whole fleet at once.

Terms, quickly. A **wave** is one slice of the fleet upgraded together. A
**canary** — named for the coal-mine bird — is the deliberately small first
wave that meets trouble while trouble is still small. A **digest pin** means
deploying by content hash (`@sha256:…`) instead of by tag: a tag is a movable
label that can be repointed at different bytes, while a digest names exactly
one artifact, forever. The **agent registry** is the control plane's
per-tenant record of agents, their versions, and their last **heartbeat** (the
periodic "still alive" check-in). **Skew** is the version distance between the
control plane and an agent. The shape of the whole process is a railway
timetable: each wave is a train that departs alone, the next never leaves
until every car of the previous one is confirmed arrived, and one missing car
stops the entire schedule until a human signs the incident book.

## The model — and what is deliberately absent

**There is no agent self-update channel.** An agent never fetches or executes new
code on its own. Update authority stays with the operator's orchestrator (Helm /
`install.sh` / your config management), exactly like any other workload — a
self-update channel would be a fleet-wide remote-code-execution primitive (one
lever that runs attacker-chosen code on every host), which is precisely what
this design refuses. The control plane's job is to **plan** waves from the
agent registry and **verify** each wave back out of it — never to push bits.

The engine is `internal/agent/rollout.go` — a pure, fully-tested state machine
(plan → advance → verify → resume) that operator tooling drives; the agent
registry is both its only input and its only evidence. It builds
**deterministic waves** from the lifecycle cohorts — canary (~5% of the fleet)
→ early (~20%) → main (the rest) — fixed at plan time by a stable hash of each
agent's id (the same id always lands in the same cohort, so membership can
never flap mid-rollout), with agents already on the target version excluded.
Planning **fails closed** on three things:

- an artifact with no recorded signature verification (you must verify it first);
- a target version outside the supported N/N-1 version-skew window against the
  control plane (the skew gate, `internal/lifecycle.Policy.Check`, accepts ±1
  minor — so an agent one minor ahead of or behind the control plane is fine);
- an empty or already-up-to-date fleet (nothing to do).

The same skew policy is also enforced **live**, independent of any rollout: an
agent outside the window is refused at registration with gRPC
`FailedPrecondition` ("upgrade required" — retrying without upgrading won't
help). The window is configurable (`PROBECTL_AGENT_SKEW_WINDOW`, default 1),
`PROBECTL_AGENT_MIN_VERSION` force-retires anything older than an explicit
floor, and development builds skip the check.

## Operator flow

### 0. Verify the artifact — and record it

Per [verify-artifacts.md](verify-artifacts.md), confirm the artifact was built
by this repository's release workflow before you plan anything. The two
artifact kinds verify differently:

- **Container images** are **cosign-keyless signed by digest** and also carry
  **SLSA provenance + SBOM attestations**. Provenance is a signed build receipt
  naming the workflow and commit that produced the image; an SBOM — software
  bill of materials — is its ingredient list; an attestation is such a
  statement signed and attached to the image. Resolve the exact digest you will
  deploy and verify that digest before planning:

  ```sh
  IMG=ghcr.io/imfeelingtheagi/probectl-ebpf-agent:<version>
  DIGEST="$(docker buildx imagetools inspect "$IMG" --format '{{.Manifest.Digest}}')"
  cosign verify \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    --certificate-identity-regexp \
      "^https://github.com/imfeelingtheagi/probectl/\.github/workflows/release\.yml@refs/tags/" \
    "ghcr.io/imfeelingtheagi/probectl-ebpf-agent@${DIGEST}"
  ```

- **VM binaries** are **cosign-keyless signed** — signed via a short-lived
  certificate tied to the release workflow's identity, so there is no
  long-lived signing key to steal. Run the `cosign verify-blob` checks from
  [verify-artifacts.md](verify-artifacts.md) against the binary and the signed
  `checksums.txt` — the identity pin proves the signature chains to this
  repository's release workflow running on a release tag.

The plan requires the exact **digest**, the verification **method**, and **who
verified** it — an unattested artifact refuses to plan.

### 1. Plan

Snapshot the fleet from the registry (`GET /v1/agents`) and plan. Waves render
like `canary[3]=pending early[11]=pending main[46]=pending`. The wave
membership — the exact agent ids in each wave — is the orchestrator's worklist.
The operator surface is deliberately **API + runbook only** (`web/src/surfaces.ts`
declares it as federated): ordinary tenant navigation should not hide the fact
that this is a fleet-change workflow driven by external orchestration, not a
point-and-click agent self-update channel.

```sh
curl -X POST "$PROBECTL_URL/v1/rollouts" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "v0.2.1",
    "digest": "sha256:<exact artifact digest>",
    "verify_method": "cosign verify-blob ...",
    "canary_percent": 5,
    "early_percent": 20
  }'
```

### 2. Advance one wave

`Advance` releases exactly **one** wave (never two, never out of order) and
starts its verify window (default 15 m) — the train departs, and the clock for
confirming its arrival starts. Apply that wave with your orchestrator,
**by digest**:

```sh
curl -X POST "$PROBECTL_URL/v1/rollouts/$ROLLOUT_ID/advance" \
  -H "Authorization: Bearer $TOKEN"
```

- **Kubernetes** (the agent chart): `helm upgrade probectl-agent
  deploy/helm/probectl-agent --reuse-values --set
  image.tag="<version>@sha256:<digest>"`. Scope a wave to a set of nodes with
  `nodeSelector` or a separate release per ring. In clusters with Kyverno,
  apply `deploy/admission/probectl-agent-image-integrity.kyverno.yaml` so
  admission also enforces the release-workflow cosign signature on that digest.
- **VMs**: `sudo deploy/agent/install.sh ./probectl-ebpf-agent-<version>` on the
  wave's hosts (after `cosign verify-blob`).

### 3. Verify from the registry — the agents are the evidence

Every wave member must re-register on the **target version** with a **fresh
heartbeat** (seen within the last 5 m). The orchestrator's "applied
successfully" is *not* proof — only the agent itself reporting back, alive and
on the new version, counts. All good → the wave completes and you can advance
the next one. Stragglers still inside the window: keep waiting, re-verify.

The `probectl_agents` Ansible role follows the same rule. Its local
`systemctl is-active` check is only a liveness precheck; by default the role also
queries `GET /v1/agents/{id}` and waits until the tenant-scoped registry row has
the expected `agent_version`, `online` status, and a `last_seen_at` newer than
the start of the role run. Provide `probectl_control_api_url`,
`probectl_control_api_token` (an `agent.read` bearer token from vault),
`probectl_registry_agent_id`, and optionally
`probectl_registry_expected_version`/`probectl_registry_heartbeat_freshness_seconds`.
Missing API credentials or a stale registry row fail the play closed.

```sh
curl -X POST "$PROBECTL_URL/v1/rollouts/$ROLLOUT_ID/verify" \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Halt-on-error

Once the verify window expires, **any** straggler — still on the old version,
reporting nothing, or vanished from the registry entirely ("upgraded, then went
dark") — **halts the whole rollout** and names the offending agents. A halted
rollout exposes no current wave, refuses both Advance and Verify, and never
resumes on its own.

### 5. Resume is explicit

After you remediate (roll the node back, replace it, or fix the artifact),
`Resume` takes a **written remediation note** and returns the failed wave to the
applying state with a fresh window. That note is the audit trail of what went
wrong mid-rollout.

## Properties worth relying on

| Property | Where it is enforced |
|---|---|
| Verified artifacts only | the plan refuses without digest + method + verifier; deploys are by digest |
| No self-update | nothing in the agent fetches code — orchestrator-only |
| Skew gate stays green | the plan refuses any target outside N/N-1 vs the control plane |
| Deterministic waves | stable-hash cohorts, fixed at plan time, with sorted membership |
| No overlap / no skipping | Advance refuses while a wave is still unverified |
| Halt-on-error | registry-verified — stragglers or dark agents past the window freeze the train |
| Mid-rollout safety | N/N-1 means old and new agents coexist on the bus throughout |

**Rollback** is the same machine pointed backwards: plan a rollout to the
previous (still-verified) version. The same skew window that lets waves coexist
going forward lets them coexist coming back.
