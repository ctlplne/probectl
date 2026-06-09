# The probectl eBPF agent — security whitepaper

The standalone document a buyer's security team reviews before privileged code
runs on their hosts. Every claim here is enforced by code or a CI gate, cited
inline so you can check it yourself; the deeper, system-wide view is
[threat-model.md](threat-model.md).

## 1. What it is, in one paragraph

A single static Go binary that loads CO-RE eBPF programs to *observe* L3/L4 flows
(and, only with explicit consent, TLS-plaintext L7 metadata) on a host,
aggregates them in userspace, and publishes tenant-tagged batches to the
operator's own Kafka over TLS. ("CO-RE" — Compile Once, Run Everywhere — means
the programs relocate themselves against whatever kernel they land on, so there
is no per-kernel build to trust.) The agent enforces nothing, captures payloads
nowhere by default, never fetches code, and runs with two Linux capabilities.

## 2. Privilege posture — exact, declared, enforced

A capability is a fine-grained slice of root's power. The agent takes the two it
needs to load and attach observation programs, and nothing else.

| Surface | Posture | Enforced by |
|---|---|---|
| Capabilities | **drop ALL; add `CAP_BPF` + `CAP_PERFMON`** (kernels ≥ 5.8). `CAP_SYS_ADMIN` only as the documented 5.4–5.7 fallback. Never `CAP_NET_ADMIN`, never `CAP_SYS_PTRACE`, never unrestricted root | systemd unit (`deploy/agent/probectl-ebpf-agent.service`: non-root user + ambient caps); Helm chart (`deploy/helm/probectl-agent`) — both CI-gated (`scripts/check_helm_hardening.sh` asserts the pair, and that `SYS_ADMIN` appears only in legacy mode) |
| Seccomp | default-deny (`EPERM`) syscall allowlist: Go runtime + `bpf` + `perf_event_open` + socket I/O. No mount, no module load, no ptrace, no reboot/kexec | `deploy/agent/seccomp.json`; the unit ships an equivalent `SystemCallFilter` |
| Filesystem | read-only root; only `/var/lib/probectl` writable; BTF mounted read-only | unit `ProtectSystem=strict`; chart `readOnlyRootFilesystem: true` (CI-asserted) |
| Kubernetes nuance | the container runs uid 0 *with everything dropped except the pair* — Kubernetes grants added capabilities to the root user only; the VM unit is fully non-root via ambient capabilities | documented in `deploy/agent/README.md`; chart render CI-asserted |

## 3. Observe-only — a proof, not a promise

The strongest claim in this document is that the agent *physically cannot* block,
drop, or redirect traffic — it can only watch. Two independent mechanisms back
that up:

- **A static gate on program type.** eBPF programs come in types. Some can only
  observe (tracepoint, uprobe, ring buffer); others can act on packets (XDP,
  tc/qdisc, cgroup enforcement, kprobe-writes). A CI gate
  (`internal/ebpf/observeonly_test.go`) statically refuses any policy-capable
  type — only observation types may exist in the tree. An enforcement program
  cannot be merged.
- **Load-and-attach on real kernels.** The `ebpf-kernel-matrix` CI job loads and
  attaches **every** program on real LTS kernels (5.15 and 6.6) under QEMU on
  every pass — so the shipped bytecode is exactly what was reviewed, proven
  loadable, and proven incapable of enforcement.

This is a hard product guardrail (CLAUDE.md §7.8–7.9): detection is a signal,
never an inline IPS.

**Object integrity.** A SHA-256 manifest of the compiled eBPF objects is baked
into the binary at build time. Before the kernel ever sees a program, the loader
verifies the embedded bytes against that manifest and refuses on any mismatch or
missing entry (`internal/ebpf/integrity.go`). A tampered object never loads.

## 4. Data categories — what is captured, and what never is

| Category | Captured? | Detail |
|---|---|---|
| L3/L4 flow metadata | **Yes** | 5-tuple, byte/packet counts, direction, state, PID/process name; tenant-stamped at emission |
| Service edges | **Yes** | aggregated process↔service relationships (the service map) |
| Packet payloads | **No** | no program captures packet bodies |
| TLS-plaintext L7 metadata | **Off by default — double-keyed consent** | requires BOTH `l7_capture_enabled` AND `l7_capture_consent_tenant` naming this agent's exact tenant; the config refuses one without the other (`internal/ebpf/config.go`) |
| HTTP bodies under L7 capture | **No by default** | the redaction boundary zeroes bodies in place; headers and protocol metadata survive; non-HTTP traffic keeps only a 128-byte detection window (`internal/ebpf/l7policy.go`, CI-tested); a `full` mode exists for consented debugging only |
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

Defaults (Helm chart): requests 50m CPU / 64Mi, **limits 500m / 256Mi**. When the
kernel's ring buffer fills under load, the dropped flows are **counted and
exported, never silently discarded** — a dropped flow is a correctness gap in an
observability tool, so it must be visible.

Measured numbers (methodology and the CI tripwire are in
[agent-overhead.md](../agent-overhead.md)) — userspace pipeline, on the defined
50-peer × 8-port profile:

| Metric | Value |
|---|---|
| Pipeline throughput | **881k events/s** (wall clock) |
| CPU per event | **1.75 µs** → ≈ 0.18% of one core at 1k flows/s |
| Max RSS during the run | **29 MiB** |
| L7 redaction | 73 ns per 1.1 KiB payload, zero allocations |

A throughput floor runs in **every** `make test`, so a regression against the
"lightweight" claim fails CI. One row is still open: the live, on-host ring-buffer
overhead on reference hardware is measured in the userspace pipeline but awaits a
human-scheduled reference-hardware run (tracked in the same doc).

## 7. Identity, transport, and tenancy

The agent's identity is bound to exactly one tenant, and it cannot speak in the
clear. Two transports are involved:

- The **canary / enterprise agent** speaks gRPC over **mTLS** with a SPIFFE-style,
  **tenant-bound** identity and a **mandatory trust-domain pin** — a certificate
  from the wrong trust domain is rejected at the handshake.
- The **eBPF agent** publishes to Kafka with TLS **required**: plaintext is
  *refused* unless a dev-only override is set explicitly, enforced both at
  runtime (`internal/bus/security.go`) and at Helm chart render time.

Every emitted record carries the agent's single bound tenant, so an agent
physically cannot emit data as another tenant.

## 8. Updates and signing — deliberately boring

**There is no self-update channel.** The agent never fetches or executes code —
removing the single most dangerous capability a fleet agent can have. Upgrades are
operator actions through an external orchestrator (Helm / `install.sh` / config
management), rolled out in staged waves with registry verification and
halt-on-error (see [fleet-rollout.md](../ops/fleet-rollout.md)). The rollout
planner **refuses any artifact without a recorded cosign signature verification**
(verify commands in [verify-artifacts.md](../ops/verify-artifacts.md)). Releases
are cosign-signed (keyless) with SPDX SBOMs and will not cut from a red CI run.

## 9. Install artifacts

- **Kubernetes:** the `deploy/helm/probectl-agent` DaemonSet chart. The full
  privilege contract is declared in the artifact itself and CI-gated (lint +
  hardening assertions + kubeconform), with fail-closed rendering — no tenant
  configured → refuse; plaintext bus without the explicit dev flag → refuse.
- **VM / bare metal:** `deploy/agent/install.sh` — installs the local binary, a
  dedicated non-root system user, the hardened systemd unit, and a fail-closed
  sample config.

Both paths are air-gap friendly: neither downloads anything at install time.

## 10. Review pointers

The eBPF programs live in `internal/ebpf/` (the C is in `bpf/`, around 200 lines),
the CI gates named throughout this doc are in `.github/workflows/ci.yml`, and the
drills and benchmarks are listed under `make help`. Report vulnerabilities via
[SECURITY.md](../../SECURITY.md).
