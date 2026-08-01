# Dependency policy

## The idea in one line

Every piece of third-party code probectl uses is **pinned to an exact version,
verified cryptographically, and upgraded deliberately by a human**. The
**supply chain** is everything that flows into the build from outside —
libraries, compilers, base images, CI actions: code you run but didn't write.
A floating
version (`@latest`, an unpinned base image, a loosely-ranged package) is a
supply-chain input that nobody reviewed — so probectl doesn't allow any. This page
is the map of *where* the pins live and *what* enforces them.

Why so strict? probectl is self-hosted software that handles tenant data and, in
the eBPF agent, runs code in the kernel. A compromised or surprise-broken
dependency is a security and availability risk, not just a build annoyance. Pin
exactly, verify, upgrade on purpose.

## Product self-sufficiency and license posture

probectl's sellable product must remain complete without a separately licensed
application. Native screens, APIs, storage paths, and operational workflows are
the authoritative surfaces. Open-protocol compatibility is welcome, but the
client stays operator-supplied and optional; an integration must not quietly
become a required runtime.

For third-party code, prefer MIT and equivalently permissive licenses (BSD, ISC,
Apache-2.0, 0BSD, and similar). A non-permissive runtime dependency is an
architecture and commercial-distribution decision, so it requires explicit
product-owner approval plus license review before it enters build, CI,
packaging, Compose, Helm, or the air-gap bundle. In particular, do not bundle or
pin an AGPL/GPL/SSPL/BSL dashboard product merely to complete or test a probectl
surface. Build that surface natively; keep compatible APIs vendor-neutral.

Grafana is the concrete boundary example: `/v1/grafana` is probectl's own
tenant-safe Prometheus-compatible wire API, not a Grafana code dependency.
Files under `deploy/grafana/` are optional configuration examples for operators
who already chose that client. No Grafana image, plugin, runtime, or license is
part of the probectl distribution or required for its UI/test definition of
done. `scripts/check_dependency_license_policy.sh`, run by
`make third-party-gate`, rejects a Grafana runtime reference and rejects
strong-copyleft or unknown runtime licenses in the generated inventory.

## How everything is pinned

| Surface | Mechanism | Enforced by |
|---|---|---|
| Go modules | exact versions in [`go.mod`](../go.mod), checksums in `go.sum` (verified against the Go checksum database on download) | `go build` fails on any checksum mismatch |
| Dev / codegen tools (buf, protoc-gen-go / -go-grpc, golangci-lint, govulncheck) | exact versions at the top of the [`Makefile`](../Makefile); installed as Go modules (so they're checksum-verified) — never `@latest`, never a curl-pipe install | the `proto` job's generated-code drift check; the supply-pins gate |
| GitHub Actions | full commit-SHA pins (not `@v3` tags) | `scripts/check_action_pins.sh` (the `action-pins` CI job) |
| Container images and Dockerfile frontends (compose, Helm, CI services, `# syntax=`) | digest pins (`@sha256:...`) on infrastructure images, probectl production workloads, and BuildKit frontends. The optional analyzer runtime uses `python:3.12.10-slim-bookworm@sha256:fd95…88db`. | the supply-pins gate (including the templated primary Helm image contract), Helm render gate, review, and the scheduled security scan |
| npm (`web/`, `browser-worker/`) | exact direct versions in `package.json`, resolved integrity records in `package-lock.json`, installed with `npm ci` | the supply-pins gate rejects semver ranges in direct manifests; `npm audit` runs in the `web` and `security-scan` jobs |
| Go toolchain | the `go` directive in `go.mod` (exact patch), a verified upstream release | see [`build/toolchain.md`](build/toolchain.md) |

Three mechanisms recur in that table. A **checksum** is the cryptographic
fingerprint of a file's exact bytes — change one bit and the fingerprint
changes, so a verified download is provably the published one. A **lockfile**
(`go.sum`, `package-lock.json`, `requirements-dev.lock`) records the resolved
version *and* checksum of every package in the dependency tree, so an install
reproduces the recorded set instead of re-resolving whatever is newest. And a
**digest pin** addresses a container image by the hash of its content
(`@sha256:...`) rather than by a tag a registry owner can quietly re-point —
ordering by serial number instead of by model name: the model name can be
reissued on different goods; the serial number can't.

The supply-pins gate (`scripts/check_supply_pins.sh`, run by the `action-pins`
job) is the backstop that mechanically fails the build on a floating reference:
a `:latest` image ref anywhere under `deploy/`, a tag-only (non-digest) `image:`
or camelCase `<name>Image:` value under `deploy/helm` (e.g. the privileged agent
`installerImage:`), a mutable scalar or nested job container, service, or matrix
`image:` value in `.github/workflows` (unresolved image expressions fail closed),
a tag-only Dockerfile `# syntax=docker/dockerfile` frontend, a `go install` in
CI or the `Makefile` without an exact `@vX.Y.Z`, or a
`pip install` without exact `==` pins, `--require-hashes`, or `--no-deps`. It
also checks the direct npm manifests and the analyzer `pyproject.toml` for
range syntax (`^`, `~`, `>=`, and friends), because a lockfile pins resolved
bytes but the manifest still states upgrade intent.

## Upgrade cadence

- **Human-driven, never automated.** Pins are bumped by a person who reads the
  release notes — there is no auto-update bot opening batched dependency PRs.
  Each bump lands as **its own pull request** through the **full** gate set
  (unit/integration tests, the isolation suites, fuzz-smoke, and the eBPF
  kernel-matrix where relevant). Never batched, never auto-merged.
- **Security releases** are handled out-of-band on the same gates. `govulncheck`
  and Trivy also run on a weekly schedule
  ([`.github/workflows/security-scan.yml`](../.github/workflows/security-scan.yml))
  **and** on every PR, so a newly-disclosed vulnerability in an *unchanged* pin
  goes red on its own — you don't have to be mid-upgrade to find out.
- **npm audit policy is explicit and expiring.** Critical npm advisories always
  fail. High advisories fail unless they are listed in
  [`docs/security/npm-audit-policy.json`](security/npm-audit-policy.json), and
  still before its `expires_at` date when it is active. Every exception must
  match the **exact complete High advisory set, advisory range, and installed
  version** for every named package. A changed version or range therefore
  becomes a fresh failure instead of inheriting an old risk decision. A
  production exception must additionally carry an offline applicability guard.
  A dev-only `standing` exception may remain dormant when its exact advisory is
  absent; it cannot apply to production or suppress a stale active advisory
  after expiry.

  `GHSA-qwww-vcr4-c8h2` is accepted as documented risk for exactly React Router
  `7.18.1` and official affected range `>=7.12.0 <8.3.0` through `2026-10-31`
  (re-verified 2026-08-01: the only patched release is the 8.3.0 major; the
  newest 7.x, `7.18.2`, is still inside the affected range) only while
  [`scripts/check_web_router_mode.mjs`](../scripts/check_web_router_mode.mjs)
  proves the shipped UI remains a client-only
  `<BrowserRouter basename="/ui">` SPA with no RSC API, RSC build dependency,
  RSC entrypoint, or server-action directive.

  `GHSA-mh99-v99m-4gvg` has a dev-only standing entry for exactly historical
  transitive `brace-expansion@1.1.16` and official affected range `<=5.0.7`.
  That package was build/lint tooling only, never received untrusted product
  input, and has no patched 1.x. The current glob chain already uses patched
  `brace-expansion@5.0.8`, so the entry is dormant and accepts no present
  finding. A recurrence at a different version, a different advisory or range,
  or any production reachability fails as new work.

  `GHSA-fx2h-pf6j-xcff` is accepted as documented risk for exactly direct
  devDependency `vite@5.4.21` and official affected range `<=6.4.2` through
  `2026-09-30`. It is a Windows-only alternate-path bypass in the Vite
  `server.fs.deny` development server. Vite is build tooling, not part of the
  shipped browser bundle or Go binaries, and the production-only audit remains
  unaffected. Decision of record 2026-08-01: the Vite 8 upgrade (8.2.0 line at
  decision time) lands before the `2026-09-30` boundary with the web build,
  bundle-budget, rendered-a11y, and coverage gates green; the minimal patched
  hop to `6.4.3` was rejected as landing two majors behind. The boundary is a
  landing deadline, not a rolling renewal. A different advisory or range, any
  installed-version change, production reachability, audit clearance, or
  expiry fails closed; therefore production adoption or the planned Vite bump
  automatically reopens the decision.

  The production `npm audit --omit=dev --json` report passes through the same
  policy checker with `--omit-dev`, so the full report owns dev-only exception
  freshness while production remains independently gated. Critical, another
  High, expiry of an active exception, a missing/malformed report, RSC
  adoption, version/range drift, or a non-standing exception whose advisory
  disappeared all fail closed.

- **Tool pins** (the `Makefile` block) are bumped deliberately and committed
  *together with their effects* — e.g. a protobuf-plugin bump ships with the
  regenerated `internal/gen` tree in the same commit, because the `proto` job
  fails if the committed generated code doesn't match the pinned plugins.

## Risk register: pre-1.0 dependencies on privileged paths

Most dependencies are stable, post-1.0 libraries. A couple sit on sensitive paths
and earn an explicit note.

### `cilium/ebpf` v0.21.0 — the one that matters

The eBPF agent loads kernel programs through `cilium/ebpf`, which is **pre-1.0**:
its API contract explicitly allows breaking changes between minor versions. It
sits on probectl's most privileged path — the `bpf()` syscall, `CAP_BPF` (the
Linux capability that permits loading eBPF programs into the kernel).

Why this dependency is accepted, with eyes open:

- It is the de-facto-standard pure-Go eBPF library, maintained by the Cilium org
  and used in production by Cilium / Tetragon / Inspektor-Gadget at far larger
  scale than probectl. The only more-"mature" alternative is a cgo dependency on
  libbpf, which brings its own costs.
- **Pre-1.0 here means API instability, not kernel-safety instability.** The
  kernel verifier (the in-kernel static checker every BPF program must pass
  before it is allowed to run) — not the library — is the safety boundary for
  what a loaded
  program is allowed to do, and probectl's programs are observe-only, with a CI
  gate (`internal/ebpf/observeonly_test.go`) enforcing that invariant
  independently of the library.
- The blast radius of a bad upgrade is **availability of the eBPF plane** (the
  agent fails to *load* programs), not data corruption or privilege escalation.
  Load failures are loud (lockdown explainers, attach-failure metrics) and the
  agent degrades to fixture/disabled mode rather than crashing the host.

Controls specific to this dependency:

1. **Exact pin** in `go.mod` (`v0.21.0`), checksum-verified like everything else.
2. **Kernel-matrix CI** — every change, including a `cilium/ebpf` bump, *loads and
   runs* the real programs across the supported LTS kernel range under QEMU. An
   API or behavior break surfaces there, in CI, not on a customer's host.
3. **Digest-verified embedded objects** — the loader refuses tampered or stale BPF
   objects before any kernel call, independent of the library version.
4. **Upgrade rule** — treat a minor-version bump of this library with the same
   care as a kernel bump: read the release notes for verifier/loader changes, and
   require kernel-matrix + fuzz-smoke + the agent-overhead bench green.
5. **1.0 watch** — when `cilium/ebpf` tags v1.x, move to it in its own PR and drop
   this caveat from the page.

### Other notable pins

- `gosnmp` (`v1.43.2`, device polling — *untrusted* device input): fuzzed via
  `FuzzSNMPPoll` (`internal/device/snmp_fuzz_test.go`); a malformed device
  response must never panic the agent.
- OTLP protobufs (`go.opentelemetry.io/proto`): wire-compatibility on probectl's
  *own* schemas is governed by the `proto` job's breaking-change gate; OTLP ingest
  is fuzzed for parse safety.

## When NOT to add a dependency

The default is **no**. A new dependency has to clear all of:

- a maintained upstream,
- a license compatible with the open-core editions model (see
  [`editions.md`](editions.md)),
- no phone-home behavior (a
  [non-negotiable](../CONTRIBUTING.md#non-negotiables)),
- and a note in the PR naming what it replaces.

**Crypto never comes from a new dependency** — it goes through `internal/crypto`
only, so a FIPS-validated module can be compiled in (also a
[non-negotiable](../CONTRIBUTING.md#non-negotiables); a CI lint guard rejects
primitive imports elsewhere). And adding an external dependency is a design
discussion *before* the code, not a fait accompli in a feature PR — open the
discussion first (see [`../CONTRIBUTING.md`](../CONTRIBUTING.md)).

## Deploy-time pinning (operators)

The repo pins what *it* controls; operators should pin what *they* deploy:

- **Images:** shipped production Compose and the primary control-plane Helm
  chart require digest-pinned workload references; tag-only control images fail
  closed. Dockerfiles also digest-pin their base images. Resolve the signed
  release or approved-mirror digest before deployment:

  ```sh
  docker inspect --format='{{index .RepoDigests 0}}' <image>
  ```

  The privileged eBPF agent Helm chart goes further: it refuses to render unless
  `image.tag` includes an `@sha256:` digest, and it renders the Kyverno
  image-integrity policy by default so admission verifies that digest's cosign
  signature against the probectl release workflow identity. `image.allowTagOnly=true`
  is an explicit break-glass for already-verified private registries, and
  disabling the policy requires an `admission.imageIntegrity.acceptedRisk` note.
  The standalone `deploy/admission/probectl-agent-image-integrity.kyverno.yaml`
  manifest is the GitOps form for clusters that manage admission policy
  separately from the workload chart.

- **Python (the analyzer):** the shipped sidecar runtime is **hash-locked** in
  `analyzer/requirements.lock`; the test/tool set is hash-locked in
  `analyzer/requirements-dev.lock` (generated with
  `uv pip compile pyproject.toml --extra dev --generate-hashes`). Runtime and
  dev dependencies in `pyproject.toml` use exact `==` pins; CI installs the lock
  with `--require-hashes` and refuses any drift between the lock and
  `pyproject.toml`. Standalone tools (`ruff`, `black`, `pyyaml`, `uv` itself)
  are exact-pinned in the workflow.

## Software bill of materials (SBOM)

An **SBOM** is the machine-readable parts list of a piece of software — every
dependency, with versions — the document a security team greps the day a CVE
drops to answer "do we ship that anywhere?". CycloneDX and SPDX are the two
standard SBOM document formats; probectl produces both at different points.
Every CI run produces a **CycloneDX SBOM** of the Go module graph
(`probectl-sbom.cdx.json`) via the `sbom` job, which installs `cyclonedx-gomod`
pinned and checksum-verified (`go install ...@v1.7.0`) — no third-party action.
The SBOM is uploaded as a build artifact (retained 90 days) alongside the scan
outputs, so the dependency posture is always evidenced, not asserted. Releases
additionally ship a signed SPDX SBOM as a release asset (see
[`releasing.md`](releasing.md)).

The human-readable license inventory is
[`third-party-licenses.md`](third-party-licenses.md) plus [`../NOTICE`](../NOTICE),
regenerated by `scripts/gen_third_party.sh` from the Go module graph, the npm
lockfiles (`web/` and `browser-worker/`), and the Python analyzer lock. Release
and air-gap evidence carries the same unified inventory beside SBOM/signature
artifacts, so an offline operator can answer "do we ship React, Playwright, or
structlog?" without network access.
