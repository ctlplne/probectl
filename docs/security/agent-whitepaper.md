# The probectl eBPF agent — security whitepaper (U-034)

v1.0 — 2026-06-07. The standalone document a buyer's security team reviews
before privileged code runs on their hosts. Every claim here is enforced by
code or CI cited inline; the deeper system view is
[threat-model.md](threat-model.md).

## 1. What it is, in one paragraph

A single static Go binary that loads CO-RE eBPF programs to observe L3/L4
flows (and, only with explicit consent, TLS-plaintext L7 metadata) on a
host, aggregates them in userspace, and publishes tenant-tagged batches to
the operator's own Kafka over TLS. It enforces nothing, captures payloads
nowhere by default, never fetches code, and runs with two capabilities.

## 2. Privilege posture — exact, declared, enforced

| Surface | Posture | Enforced by |
|---|---|---|
| Capabilities | **drop ALL; add `CAP_BPF` + `CAP_PERFMON`** (kernels ≥ 5.8). `CAP_SYS_ADMIN` only as the documented 5.4–5.7 fallback. Never `CAP_NET_ADMIN`, never `CAP_SYS_PTRACE`, never unrestricted root | systemd unit (`deploy/agent/probectl-ebpf-agent.service`: non-root user + ambient caps); Helm chart (`deploy/helm/probectl-agent`) — both CI-gated (`scripts/check_helm_hardening.sh` asserts the pair, and that `SYS_ADMIN` appears only in legacy mode) |
| Seccomp | default-deny (`EPERM`) allowlist: Go runtime + `bpf` + `perf_event_open` + socket I/O. No mount, no module load, no ptrace, no reboot/kexec | `deploy/agent/seccomp.json` (U-052); unit ships an equivalent `SystemCallFilter` |
| Filesystem | read-only root; only `/var/lib/probectl` writable; BTF mounted read-only | unit `ProtectSystem=strict`; chart `readOnlyRootFilesystem: true` (CI-asserted) |
| Kubernetes nuance | the container runs uid 0 *with everything dropped except the pair* — Kubernetes grants added capabilities to root only; the VM unit is fully non-root via ambient capabilities | documented in `deploy/agent/README.md`; chart render CI-asserted |

## 3. Observe-only — a proof, not a promise

The agent **cannot enforce**: a CI gate (`internal/ebpf/observeonly_test.go`)
statically refuses any policy-capable BPF program type (XDP, tc/qdisc,
cgroup enforcement, kprobe-writes); only observation types (tracepoint,
uprobe, ring buffer) may exist in the tree. Separately, the
`ebpf-kernel-matrix` CI job **loads and attaches every program on real LTS
kernels (5.15, 6.6) under QEMU on every pass** (U-021) — so the shipped
bytecode is exactly what was reviewed, proven loadable, and incapable of
enforcement. CLAUDE.md §7.8–7.9 make this a hard product guardrail:
detection is a signal, never an IPS.

Object integrity: a SHA-256 manifest of the compiled BPF objects is baked
into the binary at build; loaders verify the embedded bytes against it
**before the kernel ever sees them** and refuse on mismatch or a missing
entry (U-014, `internal/ebpf/integrity.go`).

## 4. Data categories — what is captured, and what never is

| Category | Captured? | Detail |
|---|---|---|
| L3/L4 flow metadata | **Yes** | 5-tuple, byte/packet counts, direction, state, PID/process name; tenant-stamped at emission |
| Service edges | **Yes** | aggregated process↔service relationships (the service map) |
| Packet payloads | **No** | no program captures packet bodies |
| TLS-plaintext L7 metadata | **Off by default — double-keyed consent** | requires BOTH `l7_capture_enabled` AND `l7_capture_consent_tenant` naming this agent's exact tenant (U-003); config refuses one without the other (`internal/ebpf/config.go`) |
| HTTP bodies under L7 capture | **No by default** | the redaction boundary zeroes bodies in place; headers/protocol metadata survive; non-HTTP keeps only a 128-byte detection window (`internal/ebpf/l7policy.go`, CI-tested); `full` mode exists for consented debugging only |
| Host files, env, user data | **No** | no collection paths exist |

The Go-TLS limitation is disclosed, not hidden: `crypto/tls` does not use
libssl, so Go processes are outside L7 capture today
(`docs/ebpf-feasibility.md` §7).

## 5. Kernel compatibility

| Kernel | Support | Notes |
|---|---|---|
| ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`) | **Supported** — `CAP_BPF`+`CAP_PERFMON` | all mainstream LTS distros; CO-RE relocates against the running kernel |
| 5.15 / 6.6 LTS | **CI-proven every pass** | loaded + attached under QEMU (`ebpf-kernel-matrix`) |
| 5.4–5.7 | best-effort | `CAP_SYS_ADMIN` fallback (`capabilityMode: legacy`) |
| < 5.4 / no BTF | unsupported for live capture | fixture/replay mode still works (no kernel programs) |

Memory locking: BPF maps/ring buffer need `RLIMIT_MEMLOCK` (the unit and
chart set it); kernels ≥ 5.11 account via memcg.

## 6. Resource bounds and measured overhead

Defaults (Helm chart): requests 50m CPU / 64Mi, **limits 500m / 256Mi**.
Ring-buffer backpressure **drops are counted and exported, never silent**
(a dropped flow is a correctness gap in an observability tool).

Measured (U-051, methodology + tripwire in
[`docs/agent-overhead.md`](../agent-overhead.md)) — userspace pipeline,
defined 50-peer × 8-port profile:

| Metric | Value |
|---|---|
| Pipeline throughput | **881k events/s** (wall) |
| CPU per event | **1.75 µs** → ≈0.18% of one core at 1k flows/s |
| Max RSS during the run | **29 MiB** |
| L7 redaction | 73 ns / 1.1 KiB payload, zero allocations |

A throughput floor runs in **every** `make test` — a regression in the
"lightweight" claim fails CI. The live ring-buffer numbers on reference
hardware are the one pending row (BLOCKED-ON-HUMAN, same doc).

## 7. Identity, transport, and tenancy

The canary/enterprise agent speaks mTLS gRPC with SPIFFE-style,
**tenant-bound** identity and a **mandatory trust-domain pin** (U-011); the
eBPF agent publishes to Kafka with TLS required — plaintext is *refused*
unless a dev-only override is set explicitly, both at runtime (U-010,
`internal/bus/security.go`) and at chart render (U-016). Every emitted
record carries the agent's single bound tenant; an agent cannot emit as
anyone else.

## 8. Updates and signing — deliberately boring

**There is no self-update channel** (preserved strength ST-04). The agent
never fetches or executes code. Upgrades are operator actions through the
external orchestrator (Helm / `install.sh` / config management) in staged
waves with registry verification and halt-on-error (U-031,
`docs/ops/fleet-rollout.md`), and the rollout planner **refuses artifacts
without a recorded cosign verification** (C6; verify commands in
`docs/ops/verify-artifacts.md`). Releases are cosign-signed (keyless) with
SPDX SBOMs and refuse to cut from red CI.

## 9. Install artifacts

Kubernetes: the `deploy/helm/probectl-agent` DaemonSet chart — the full
privilege contract is declared in the artifact and CI-gated (lint +
hardening assertions + kubeconform), with fail-closed rendering (no tenant
→ refuse; plaintext bus without the explicit dev flag → refuse). VM/bare
metal: `deploy/agent/install.sh` — local binary, dedicated non-root system
user, the hardened unit, a fail-closed sample config. Air-gap friendly:
neither path downloads anything.

## 10. Review pointers

`internal/ebpf/` (programs in `bpf/`, ~200 lines of C), the gates named
above in `.github/workflows/ci.yml`, and the drills/benchmarks under
`make help`. Vulnerability reports: [SECURITY.md](../../SECURITY.md).
