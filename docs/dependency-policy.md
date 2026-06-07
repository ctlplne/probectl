# Dependency policy (U-081)

One page: how probectl pins, upgrades, and risk-rates third-party code. The
posture everywhere is **pin exactly, verify cryptographically, upgrade
deliberately** — a floating version is a supply-chain input nobody reviewed.

## How everything is pinned

| Surface | Mechanism | Enforced by |
|---|---|---|
| Go modules | exact versions in `go.mod`, checksums in `go.sum` (sumdb-verified) | `go build` fails on mismatch |
| Dev/codegen tools (buf, protoc-gen-go/-go-grpc, golangci-lint, govulncheck) | pinned versions at the top of the `Makefile`; installed as Go modules (sumdb-verified) — never `@latest`, never curl-pipe (U-059/U-060) | proto job's generated-code diff gate; `! grep @latest` |
| GitHub Actions | full commit-SHA pins (U-007) | `scripts/check_action_pins.sh` CI step |
| Container images (compose, CronJobs, CI services) | digest pins (U-068/C11) | review + scheduled security-scan |
| npm (web/, browser-worker/) | lockfiles + `npm ci` (U-061/U-062) | `npm audit` gate in the web job |

## Upgrade cadence

- **Dependabot weekly** across Go, npm, and Actions; each bump lands as its
  own PR through the FULL gate set (unit/integration, isolation suites,
  fuzz-smoke, kernel-matrix where relevant) — never batched, never auto-merged.
- **Security releases**: out-of-band, same gates; `govulncheck` + Trivy run in
  the scheduled security-scan workflow (C12) and on every PR, so a vulnerable
  pin surfaces even when no bump is open.
- **Tool pins** (Makefile block) are bumped deliberately and committed together
  with their effects (e.g. regenerated `internal/gen` for codegen plugins).

## Risk register: pre-1.0 dependencies on privileged paths

### `cilium/ebpf` v0.21.0 (U-081) — the one that matters

The eBPF agent loads kernel programs through `cilium/ebpf`, which is
**pre-1.0**: its API contract explicitly allows breaking changes between
minor versions. It sits on probectl's most privileged path (the `bpf()`
syscall, CAP_BPF).

Why this is accepted, with eyes open:

- It is the de-facto standard pure-Go eBPF library — maintained by the Cilium
  org, used in production by Cilium/Tetragon/Inspektor-Gadget at far larger
  scale than probectl; there is no more-mature alternative without taking a
  cgo dependency on libbpf.
- **Pre-1.0 risk is API instability, not kernel-safety instability**: the
  kernel verifier — not the library — is the safety boundary for what a
  loaded program may do, and probectl's programs are observe-only with the
  CI gate (`observeonly_test.go`) enforcing that invariant independently.
- The blast radius of a bad upgrade is **availability of the eBPF plane**
  (agent fails to load programs), not corruption or privilege escalation:
  load failures are loud (U-075 lockdown explainers, attach-failure metrics)
  and the agent degrades to fixture/disabled mode rather than crashing the
  host.

Controls specific to this dependency:

1. **Exact pin** in `go.mod` (v0.21.0), sumdb-verified like everything else.
2. **Kernel-matrix CI** (U-021): every change — including a cilium/ebpf bump —
   loads and runs the real programs on the supported kernel range under QEMU.
   An API or behavior break in a bump fails there, not on a customer host.
3. **Digest-verified embedded objects** (C9/U-014): the loader refuses
   tampered/stale BPF objects before any kernel call, independent of the
   library version.
4. **Upgrade rule**: bump on dependabot cadence; read the release notes for
   verifier/loader behavior changes; require kernel-matrix + fuzz-smoke +
   agent-overhead bench green. Treat a minor-version bump of this library
   with the same care as a kernel bump.
5. **1.0 watch**: when cilium/ebpf tags v1.x, move to it in its own PR and
   drop the pre-1.0 caveat from this page.

### Other notable pins

- `gosnmp` (device polling, untrusted device input): fuzzed via
  `FuzzSNMPPoll` (U-082); parse failures must never panic the agent.
- OTLP protobufs (`go.opentelemetry.io/proto`): wire-compat governed by the
  buf breaking gate (U-056) on our own schemas; ingest is fuzzed (U-082).

## When NOT to add a dependency

Default no. A new dependency needs: a maintained upstream, a license
compatible with the editions model (CLAUDE.md §2), no phone-home behavior
(§7.2), and a note in the PR naming what it replaces. Crypto NEVER comes from
a new dependency — `internal/crypto` only (§7.3). Asking the human first is
the rule (§9), not the exception.
