# The probectl eBPF agent — security whitepaper

The standalone document a buyer's security team reviews before privileged code
runs on their hosts. Every claim here is enforced by code or a CI gate, cited
inline so you can check it yourself; the deeper, system-wide view is
[threat-model.md](threat-model.md).

## 1. What it is, in one paragraph

A single static Go binary that loads CO-RE eBPF programs to *observe* L3/L4 flows
(and, only with explicit consent, TLS-plaintext L7 metadata) on a host,
aggregates them in userspace, and publishes tenant-tagged batches to the
operator's own Kafka over TLS. Unpacking that sentence: **eBPF** lets small,
kernel-*verified* programs run inside Linux to observe events — sandboxed, so
they can watch but not wander. ("CO-RE" — Compile Once, Run Everywhere — means
the programs relocate themselves against whatever kernel they land on, so there
is no per-kernel build to trust.) **L3/L4 flows** are network/transport-layer
conversations — who talked to whom, over which ports, how many bytes — never
the content; **L7** is the application layer (HTTP methods, hosts, status
codes). And the Kafka it publishes to is the deployment's own message bus —
nothing leaves the operator's network. The agent enforces nothing, captures
payloads nowhere by default, never fetches code, and runs with two Linux
capabilities.

Five "nevers", each proven somewhere below:

- **Never enforces** — physically cannot block, drop, or redirect traffic (§3).
- **Never captures payloads by default** — bodies are zeroed even under
  consented L7 capture (§4).
- **Never fetches or executes code** — no self-update channel exists (§8).
- **Never speaks in the clear** — plaintext transport is refused, not merely
  discouraged (§7).
- **Never emits as another tenant** — identity is bound to exactly one tenant
  (§7).

## 2. Privilege posture — exact, declared, enforced

A capability is a fine-grained slice of root's power. The agent takes the two it
needs to load and attach observation programs, and nothing else. **Seccomp**
narrows things further at the system-call level: a default-deny filter where
every syscall not on the allowlist returns an error (`EPERM`) instead of
executing — so even a fully compromised agent process cannot mount filesystems,
load kernel modules, or ptrace its neighbors, because the kernel refuses the
calls outright.

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
  tc/qdisc, cgroup enforcement, kprobe-writes). The difference is
  plumbing-deep: an observation type has no API for dropping or rewriting a
  packet, the way a camera fitting physically cannot close a valve. A CI gate
  (`internal/ebpf/observeonly_test.go`) statically refuses any policy-capable
  type — only observation types may exist in the tree. An enforcement program
  cannot be merged.
- **Load-and-attach on real kernels.** The `ebpf-kernel-matrix` CI job loads and
  attaches **every** program on real amd64 and arm64 LTS kernels under QEMU/KVM
  on every pass — so the shipped bytecode is exactly what was reviewed, proven
  loadable on those kernels, and proven incapable of enforcement. The arm64 row
  runs on a self-hosted Linux/ARM64 runner with the custom `kvm` label, and a
  missing `/dev/kvm` is a hard CI failure rather than a compile-only substitute.

This is a hard product guardrail: detection is a signal, never an inline IPS,
and nothing probectl ships takes autonomous action on a network.

**Object integrity.** A SHA-256 manifest — a list of cryptographic
fingerprints, one per compiled eBPF object — is baked into the binary at build
time. Before the kernel ever sees a program, the loader verifies the embedded
bytes against that manifest and refuses on any mismatch or missing entry
(`internal/ebpf/integrity.go`). A tampered object never loads.

## 4. Data categories — what is captured, and what never is

| Category | Captured? | Detail |
|---|---|---|
| L3/L4 flow metadata | **Yes** | 5-tuple (source/destination address, ports, protocol), byte/packet counts, direction, state, PID/process name; tenant-stamped at emission |
| Service edges | **Yes** | aggregated process↔service relationships (the service map) |
| Packet payloads | **No** | no program captures packet bodies |
| TLS-plaintext L7 metadata | **Off by default — triple-keyed consent** | requires `l7_capture_enabled`, PLUS `l7_capture_consent_tenant` exactly matching this agent's bound tenant (a mismatch is refused, `internal/ebpf/l7policy.go`), PLUS an explicit `l7_capture_scope` naming the opted-in workloads (`pid:`/`exe:`/`cgroup:`) — host-wide capture is not even expressible; the config refuses any one key without the others (`internal/ebpf/config.go`) |
| HTTP bodies under L7 capture | **No by default** | the redaction boundary zeroes bodies in place; headers and protocol metadata survive; non-HTTP traffic keeps only a 128-byte detection window (`internal/ebpf/l7policy.go`, CI-tested); a `full` mode exists for consented debugging only |
| Host files, env, user data | **No** | no collection paths exist |

The L7 probe works by attaching to supported system TLS libraries
(OpenSSL-compatible `libssl` and GnuTLS) at the exact boundary where the
*process itself* holds plaintext, which is why no key extraction or traffic
decryption is involved. The Go-TLS limitation is disclosed, not hidden:
`crypto/tls` does not use these C TLS libraries, so Go processes are outside L7
capture today (`docs/ebpf-feasibility.md` §7).

## 5. Kernel compatibility

| Kernel | Support | Notes |
|---|---|---|
| ≥ 5.8 with BTF (`/sys/kernel/btf/vmlinux`) | **Supported** — `CAP_BPF`+`CAP_PERFMON` | all mainstream LTS distros; CO-RE relocates against the running kernel |
| 5.15 / 6.6 LTS | **CI-proven every pass** | loaded + attached under QEMU (`ebpf-kernel-matrix`) |
| 5.4–5.7 | best-effort | `CAP_SYS_ADMIN` fallback (`capabilityMode: legacy`) |
| < 5.4 / no BTF | unsupported for live capture | fixture/replay mode still works (no kernel programs) |

BTF — BPF Type Format — is the kernel's machine-readable description of its own
data structures, published at `/sys/kernel/btf/vmlinux`; it is the map CO-RE
programs use to relocate themselves at load time.

Memory locking: BPF maps/ring buffer live in pinned (non-swappable) memory, so
they need `RLIMIT_MEMLOCK` headroom — the cap on how much memory a process may
pin (the unit and chart set it); kernels ≥ 5.11 account via memcg, the cgroup
memory controller, instead.

## 6. Resource bounds and measured overhead

Defaults (Helm chart): requests 50m CPU / 64Mi, **limits 500m / 256Mi**. The
ring buffer is the fixed-size in-kernel queue that hands events to userspace;
when it fills under load the kernel must drop, so the dropped flows are
**counted and exported, never silently discarded** — a dropped flow is a
correctness gap in an observability tool, so it must be visible.

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

- The **canary / enterprise agent** speaks gRPC over **mTLS** — mutual TLS,
  where *both* ends present certificates, so the control plane proves itself to
  the agent just as the agent proves itself to the control plane — with a
  SPIFFE-style, **tenant-bound** identity (SPIFFE is a standard for naming
  workloads inside certificates, as `spiffe://` URIs; the agent's URI names its
  tenant) and a **mandatory trust-domain pin** — a certificate from the wrong
  trust domain is rejected at the handshake.
- The **eBPF agent** publishes to Kafka with TLS **required**: plaintext is
  *refused* unless a dev-only override is set explicitly, enforced both at
  runtime (`internal/bus/security.go`) and at Helm chart render time.

Every emitted record carries the agent's single bound tenant, so an agent
physically cannot emit data as another tenant.

**How the mTLS agent gets that identity (first-boot bootstrap).** Enrollment is
deliberately boring and fail-closed (`internal/enroll`,
`internal/agent/identity.go`):

1. The operator generates the agent CA hierarchy once
   (`probectl-control agent-ca init`) — a CA, certificate authority, is the
   keypair whose signature makes agent identities valid — and distributes only
   the **public** trust bundle to hosts (`probectl-control agent-ca export`) —
   never a key.
2. The operator mints a **single-use, tenant-scoped join token**
   (`probectl-control enroll-token`; short-lived, stored server-side only as a
   hash, so a database read cannot recover a usable token). The token names the
   tenant — an agent can never choose its own.
3. The agent boots with `PROBECTL_AGENT_JOIN_TOKEN` (or `enroll.token_file`,
   e.g. a mounted Secret), generates its keypair locally, and submits a CSR — a
   certificate signing request, carrying only the public key for the CA to
   sign — so **the private key never leaves the host**. The server dictates
   every certificate field (SAN/EKU/TTL; CSR-requested extensions are ignored)
   and issues a short-lived (24 h) SPIFFE identity; renewal happens by rotation
   against proof of the *current* identity and can never change who the agent is.

The flow is **idempotent** — an existing identity is never re-enrolled or
overwritten — and **fail-closed**: an expired, replayed, or unknown token is a
fatal startup error (all invalid tokens are deliberately indistinguishable to
the caller), and with no token and no identity the agent simply cannot
authenticate — there is no unauthenticated fallback at any point.

**When the control plane is unreachable**, the canary agent spools results into
a disk-backed, bounded, FIFO store-and-forward buffer — results queue on local
disk in arrival order and replay when the connection returns
(`internal/agent/buffer.go`). At capacity the newest result is rejected with a
counted error rather than growing without bound — and nothing is ever sent in
the clear to compensate.

## 8. Updates and signing — deliberately boring

**There is no self-update channel.** The agent never fetches or executes code —
removing the single most dangerous capability a fleet agent can have. Upgrades are
operator actions through an external orchestrator (Helm / `install.sh` / config
management), rolled out in staged waves with registry verification and
halt-on-error (see [fleet-rollout.md](../ops/fleet-rollout.md)). The rollout
planner **refuses any artifact without a recorded cosign signature verification**
(cosign is the artifact-signing tool; verify commands in
[verify-artifacts.md](../ops/verify-artifacts.md)). Releases are cosign-signed
(*keyless*: the signature is bound to the CI build's identity in a public
transparency log, so there is no long-lived signing key to steal) with SPDX
SBOMs (software bills of materials — the parts list of each release) and will
not cut from a red CI run.

## 9. Install artifacts

- **Kubernetes:** the `deploy/helm/probectl-agent` DaemonSet chart (a DaemonSet
  runs exactly one agent pod per node). The full privilege contract is declared
  in the artifact itself and CI-gated (lint + hardening assertions +
  kubeconform), with fail-closed rendering — no tenant configured → refuse;
  plaintext bus without the explicit dev flag → refuse. The chart also renders
  the Kyverno image-integrity policy by default, so the privileged pod is admitted
  only when its digest is present and its keyless cosign signature comes from the
  tagged `release.yml` workflow.
- **VM / bare metal:** `deploy/agent/install.sh` — installs the local binary, a
  dedicated non-root system user, the hardened systemd unit, and a fail-closed
  sample config.

Both paths are air-gap friendly: neither downloads anything at install time.

## 10. Review pointers

The eBPF programs live in `internal/ebpf/` (the C is in `bpf/`, about 270 lines),
the CI gates named throughout this doc are in `.github/workflows/ci.yml`, and the
drills and benchmarks are listed under `make help`. Report vulnerabilities via
[SECURITY.md](../../SECURITY.md).
