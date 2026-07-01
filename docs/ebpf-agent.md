# eBPF host agent

## What it is

The **`probectl-ebpf-agent`** watches network activity **from inside the host's
kernel** — no sidecars, no app changes, no SDK to import. It gives you two things
with **zero instrumentation**:

- **L3/L4 flow capture** — every TCP connection a host makes or accepts, with the
  process and container behind it; and
- a **live service map** — the directed graph of "who talks to whom" built from
  those flows.

This is the shared host/L4 substrate the security, segmentation, and cost planes
later build on. The single most important thing to understand about it: it is
**observe-only**. It loads only *observation* programs and never *enforcement* —
it watches, it does not block, redirect, or modify a single packet. Think of a
court stenographer: admitted into the room to record every word, never permitted
to speak. probectl's eBPF layer is **not a CNI** (the Kubernetes networking layer
that *routes* pod traffic) **and not an inline IPS** (an intrusion-prevention
system that *drops* traffic it dislikes). (This is a hard guardrail, and a
build-failing test enforces it — see below.)

> **New to eBPF?** The **kernel** is the privileged core of the operating system
> — every packet, socket, and process on the host passes through it; **userspace**
> is everything outside it, where ordinary programs run. eBPF lets you load tiny,
> sandboxed programs *into the running Linux kernel* that fire on kernel events
> (a socket changing state, a function being called) and report what they saw
> back to userspace. It's how modern tools see all network activity on a box
> without touching the applications — the kernel already sees everything, so a
> program admitted into the kernel sees it too. The kernel verifies these
> programs can't crash or hang it before letting them run.

## How it works — the path of a flow

Here's the whole pipeline, from a packet event in the kernel to a record on the
bus:

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  subgraph kernel["kernel (only with -tags ebpf)"]
    TP["tracepoint sock/inet_sock_set_state"] --> PROG["CO-RE eBPF prog"] --> RB["ring buffer"]
  end
  RB --> LIVE["liveSource (cilium/ebpf)"]
  FIX["FixtureSource (recorded JSON)"] --> AGG
  LIVE --> AGG["Aggregator"]
  AGG --> ENR["enrich: process / cgroup / container"]
  ENR --> MAP["ServiceMap (directed edges)"]
  MAP --> EMIT["BusEmitter -> probectl.ebpf.flows (FlowBatch, OTel-shaped, tenant-keyed)"]
  AGG -. drops .-> DROPS["dropped_total metric"]
```

1. **Kernel hook.** A CO-RE eBPF program (CO-RE, "Compile Once – Run
   Everywhere", is the portability mechanism — see
   [Kernel compatibility](#kernel-compatibility)) attaches to the stable
   `sock:inet_sock_set_state` **tracepoint** — a named hook point the kernel
   itself exposes, with a documented argument layout the kernel promises not to
   break. Every time a TCP socket changes state, the program runs. It keeps the
   ones entering `ESTABLISHED` and writes the **5-tuple** (source IP + port,
   destination IP + port, protocol — the values that uniquely name a connection)
   plus the PID and command name into a **ring buffer** — a fixed-size queue
   shared between kernel and userspace, a conveyor belt of bounded length: the
   kernel places events on one end, userspace lifts them off the other, and when
   userspace falls behind, new events fall off and are *counted*, never silently
   lost (`internal/ebpf/bpf/l4flow.bpf.c`). Using a *tracepoint* (whose arguments
   carry the tuple directly) instead of fishing fields out of kernel structs is
   deliberate — it sidesteps per-kernel struct-layout drift for the common path.
2. **Userspace read.** The Go **`liveSource`** (built on `cilium/ebpf`) drains the
   ring buffer.
3. **Aggregate.** The `Aggregator` folds raw connection events into directed
   **service edges** ("host A → host B:443, N connections").
4. **Enrich.** Each flow is tagged with its process, cgroup, and container — the
   read-only `/proc` lookups that turn a bare PID into "the `nginx` container".
5. **Emit.** The `BusEmitter` marshals a batch to protobuf and publishes it to
   **`probectl.ebpf.flows`**, keyed by tenant.

### Userspace core + a gated kernel loader

The agent is split in two on purpose, so the bulk of it runs and is tested
**anywhere — kernel or not**:

- A pure-Go **userspace core** does the flow/service-edge model, the aggregator,
  process/cgroup enrichment, the capability probe, the OTel mapping, and the bus
  emitter. It drives a pluggable flow **`Source`**.
- The **live `Source`** — the CO-RE eBPF program loaded into a ring buffer — is
  compiled in **only under the `-tags ebpf` build tag**. Every other build uses
  the **`FixtureSource`** (recorded flows replayed from JSON), which is also the
  no-kernel CI path.

**Why split it this way?** The build host needs `clang` (the C compiler that
produces BPF bytecode); the *target* host needs only a BTF-capable kernel
(**BTF**, the BPF Type Format, is the kernel's machine-readable index of its own
data-structure layouts — what CO-RE relocates against) and `CAP_BPF` (a Linux
**capability**: one entry in the kernel's fine-grained permission list, granting
exactly the right to load BPF programs rather than all of root). And most CI
runners and macOS laptops can't load eBPF at all. By making the `-tags ebpf` files a separate, off-by-
default compilation unit, the default `make build` and ordinary CI need **no eBPF
toolchain and no extra dependency** — yet the shipped agent image is still the
live build (see [Building](#building)).

## L7 visibility — application calls, including over TLS

Beyond raw connections, the agent can parse **application-protocol calls** —
HTTP/1.1, HTTP/2, gRPC, DNS, and Kafka — and roll **per-call method / resource /
status / latency** onto each service edge. (**L7** is layer 7 of the network
stack, the application layer: not "host A talked to host B" but *what they said*
— the HTTP request, the DNS query, the Kafka produce.) Each call is emitted as an `L7Call`
plus an `l7_*` rollup on the `ServiceEdge`. Parsing is pure Go and kernel-
independent (`internal/ebpf/l7`), driven by the live capture layer in production
and by an L7 fixture (`PROBECTL_EBPF_L7_FIXTURE_PATH`) in CI and demos.

probectl gets the plaintext two ways:

- **Cleartext traffic:** parsed straight from socket reads/writes.
- **TLS traffic:** the **TLS plaintext** — the readable bytes that exist inside
  the application just before encryption and just after decryption — is captured
  via **uprobes** (user-space probes: breakpoint-like hooks placed on a named
  function in an ordinary program or library) on supported TLS library read/write
  functions (`SSL_write` / `SSL_read` for OpenSSL-compatible stacks and
  `gnutls_record_send` / `gnutls_record_recv` for GnuTLS). This reads the letter
  over the writer's shoulder before it's sealed, and over the reader's after it's
  opened — it never steams open the envelope in transit, so there is **no CA** (no
  certificate authority to forge the server's identity with) and **no
  man-in-the-middle** (no interception point inserted into the network path). Read
  calls are captured at the *return* uprobe, because the destination buffer is
  only filled when the call returns.

The OTel mapping (`internal/otel.L7CallAttributes`) emits `http.*` / `rpc.*` /
`dns.*` / `messaging.*` attributes per protocol. Calls are attributed to the
connection's **client→server** edge regardless of which direction completed them.

### Reading TLS plaintext is off by default and triple-gated

Reading application plaintext on a customer's host is PII-class, so live
TLS-plaintext capture (the "sslsniff" path) is **off by default** and requires
**three** explicit, independent statements before a single byte is captured (see
`internal/ebpf/l7policy.go`):

1. **`l7_capture_enabled: true`** — the master switch.
2. **`l7_capture_consent_tenant`** must equal the agent's bound tenant *exactly* —
   an explicit, per-tenant consent. (The agent is tenant-bound at registration, so
   this is a deliberate statement in *this* tenant's deployment config; absent or
   mismatched, capture stays off.)
3. **`l7_capture_scope`** — a non-empty **workload allowlist**: entries of the
   form `pid:<n>`, `exe:/abs/path`, or `cgroup:/abs/cgroup-dir`. Container/pod
   scoping is the `cgroup:` form (a container *is* a cgroup). An empty scope means
   capture refuses to start — **host-wide capture is not expressible.**

The allowlist is enforced **in the kernel**. Uprobes on shared TLS libraries fire
for *every* process that maps them, so the BPF program checks the in-kernel
`scope_tgids` / `scope_cgroups` maps and **drops a non-allowlisted process before
copying a byte** — that process's plaintext never enters the ring buffer at all.
`exe:` entries are re-resolved against `/proc` every 10 seconds, so restarts and
new workers of an opted-in binary stay in scope.

### Redaction is layered, and defaults closed

Even for an allowlisted workload, payload bodies are redacted by default
(`internal/ebpf/l7policy.go`). Redaction happens at two boundaries:

- **The kernel capture window** (`l7_capture_kernel_window`, default 1024 bytes)
  bounds how much plaintext per chunk may transit the ring buffer *at all* — a
  mail slot cut to a fixed height: only the first N bytes fit through, and what
  doesn't fit isn't shredded after delivery — body bytes past the window **never
  leave kernel space**. The BPF policy map's zero default is length-only, so an
  unprogrammed kernel ships **no** plaintext: it fails closed.
- **At the ring-buffer → userspace boundary**, on the only surviving copy, payload
  bodies are zeroed in place. This is `l7_capture_redaction: headers` (the
  default): protocol metadata (request line, headers) survives, the body is
  killed. (A consequence: HTTP/2 / gRPC call extraction is degraded under `headers`
  redaction, by design — the HPACK frames, HTTP/2's compressed header encoding,
  live in the zeroed region.)

The three redaction modes:

| Mode | What transits | What you can parse |
|---|---|---|
| `headers` (default) | metadata up to the header terminator; the body is zeroed (credential header **values** — Authorization/Cookie/Set-Cookie/Proxy-Authorization plus common `api-key`/`token`/`secret`/`credential`/`x-amz-*` headers — are also zeroed, names survive) | full L7 calls; HTTP/2-gRPC bodies degraded |
| `length` | **no payload bytes** — kernel window forced to 0; only chunk direction + true size (`DataEvent.Size`) | traffic *shape* only; no parsed L7 calls |
| `full` | everything (consented debugging only — still behind the enable+consent+scope gates) | full L7 calls including bodies |

Parser byte-counts reflect the *captured* window; `DataEvent.Size` always carries
the *true* chunk size, so loss-to-redaction is visible rather than silent.

> **Header secrecy vs. header metadata (EBPF-006).** Under the default `headers`
> mode, the **values** of credential-bearing headers (`Authorization`,
> `Cookie`, `Set-Cookie`, `Proxy-Authorization`) and common non-standard secret
> families (`X-API-Key`, `Api-Key`, `X-Amz-Security-Token`, custom `*Token*`,
> `*Secret*`, and `*Credential*` headers) are zeroed in place — only the header
> *names* and line framing survive, so bearer tokens, API keys, and session
> cookies never reach the control plane. If you need *all* header secrecy (not
> just credentials), choose `length` mode, which captures no payload bytes at all.
> This default is enforced by `TestRedactPayloadZeroesSensitiveHeaderValues` and
> `TestRedactPayloadZeroesNonStandardSecretHeaders`.

## Capture limitations (measured, not hidden)

Two real blind spots exist today. They are *documented and counted or bounded*,
not papered over:

- **Unsupported L3 families:** `l4flow` captures IPv4 and IPv6 TCP sockets. Other
  address families are filtered in the kernel and counted through the legacy
  `filtered_non_ipv4_total` flush field, so a host with unsupported families shows
  a rising counter instead of silent gaps.
- **Go's `crypto/tls`:** the L7 capture uprobes attach to the **system** TLS
  libraries (OpenSSL / BoringSSL / GnuTLS). **Go programs don't use libssl** — they
  ship their own TLS — so a Go process's L7 *plaintext* is **not captured**. This
  is a known gap (detailed in [`ebpf-feasibility.md`](ebpf-feasibility.md)): the
  established workaround disassembles the Go binary for `RET` offsets and tracks
  the goroutine ABI, a meaningfully more brittle path that's roadmapped
  separately. L4 flow and the service map still see Go processes fine — only their
  L7 plaintext is out of scope.

### TLS-library uprobe coverage

| TLS stack | Symbols | Coverage |
|---|---|---|
| OpenSSL | `SSL_write` / `SSL_read` (read at return) | ✅ |
| BoringSSL | same `SSL_*` API | ✅ if symbols resolvable / ⚠️ if stripped/static |
| GnuTLS | `gnutls_record_send` / `gnutls_record_recv` | ✅ (attaches the same way) |
| **Go `crypto/tls`** | no libssl — pure Go; `uretprobe` unsafe on Go | ⚠️ **separate strategy** (ret-offset disassembly + goroutine tracking — see [`ebpf-feasibility.md`](ebpf-feasibility.md)) |
| Stripped / static, no symbols | — | ❌ socket-layer cleartext only |

Two limits carry over from the feasibility study: **stripped or statically-linked
binaries** break uprobe symbol resolution (the agent falls back to socket
cleartext for those), and **Go-encrypted** traffic needs its own capture path.

## Privileges and the observe-only guarantee

Loading the programs needs **`CAP_BPF` + `CAP_PERFMON`** (Linux ≥ 5.8) — the
load right and the attach right respectively: attaching tracepoints and uprobes
goes through the kernel's performance-monitoring interface, which `CAP_PERFMON`
governs. Generic older kernels are unsupported because the agent requires BTF
and the BPF ring buffer; do not grant broad `CAP_SYS_ADMIN` as a workaround for a
kernel that the runtime probe marks unavailable. A `CAP_SYS_ADMIN` legacy
exception is only for hosts where the runtime probe can still confirm BTF + ring
buffer support but the platform cannot grant the split capability pair. The
capability probe and the enrichment lookups are read-only and need no privileges.

The observe-only guarantee is enforced in code, not just by convention. The agent
attaches only tracepoints / kprobes / uprobes and calls no traffic-altering
helper. A guard test (`observeonly_test.go`) **parses the eBPF C sources and fails
the build** if anyone introduces an enforcing program type or a mutating helper
(`bpf_redirect`, `bpf_override_return`, `bpf_probe_write_user`, packet-rewrite
helpers, …). The test runs in the default build — no kernel, no clang needed — so
the invariant is checked on every commit.

## Emission, OTel, and tenancy

Flow and service-edge batches are published to **`probectl.ebpf.flows`** as an
`ebpfv1.FlowBatch` protobuf, **keyed by tenant** (pooled tagging). Field names
follow OpenTelemetry `source.*` / `destination.*` / `network.*` / `process.*` /
`container.*` conventions **from the first emission**, so the OTLP layer *exposes*
them rather than remapping. `internal/otel.FlowAttributes` is the canonical
mapping and is held to the same "no invented attribute names" conformance bar as
results.

### Self-observation (drops are never silent)

A dropped flow is a correctness gap in an observability tool, so it is never
hidden. Ring-buffer backpressure is counted at the kernel branch that loses the
record: the L4 and TLS programs increment per-CPU `drop_counters` when
`bpf_ringbuf_reserve` fails, and TLS capture also counts `active_reads` stash
failures that would lose `SSL_read` correlation before userspace can see a
chunk. The live sources sum those counters on flush and fold them into
`dropped_total`.

The flush log carries both the roll-up and the reason labels:
`drop_decode_failures_total`, `drop_l4_ring_buffer_full_total`,
`drop_l7_ring_buffer_full_total`, `drop_l7_active_read_failures_total`, and
`drop_other_total`, plus `observed_total`, `l7_total`,
`l7_scope_sync_failures_total`, `l7_attach_failures`, `l7_evicted_total`,
`service_map_evicted_total`, `l7_manager_evicted_total`, and the legacy
`filtered_non_ipv4_total` unsupported-family counter. If only counters
changed and there is no flow batch to emit, the agent still logs
`ebpf counters updated` so an all-dropped window is visible — probectl observes
probectl.

## Tuning and kernel lockdown

`ring_buffer_bytes` (config, or `PROBECTL_EBPF_RING_BUFFER_BYTES`) sizes the
kernel ring buffer for the live source; it's rounded at load to a valid power-of-
two page multiple (default 16 MiB). Raise it on high-flow hosts to reduce ring-
buffer-full drops (which `dropped_total` will show you).

**Kernel lockdown** is a hardening mode (commonly enabled alongside Secure Boot)
that restricts what even a privileged process may do to the running kernel: if
the kernel runs in lockdown **confidentiality** mode, the `bpf()` syscall — the
one door every BPF load goes through — is blocked *even with* `CAP_BPF`. The
capability probe reports this explicitly (`lockdown="confidentiality"`, mode
unavailable) and a load attempt returns a clear message instead of a bare
`EPERM`. Boot without `lockdown=confidentiality` (integrity mode is fine) to run
the agent.

## Kernel compatibility

CO-RE ("Compile Once – Run Everywhere" — the program is compiled once, and the
loader re-aims its memory reads against the *running* kernel's BTF at load time,
so one shipped object fits every supported kernel) needs a **BTF-exposing
kernel** and the **BPF ring buffer**, both mainstream from **Linux 5.8** — that
pair is the hard floor. On a BTF-less kernel the capability probe reports eBPF
**unavailable** (the reason string points at **BTFHub** — a public archive of
pre-generated BTF files for older kernels that didn't ship their own — as a
manual avenue; no automatic external-BTF fallback ships today). The full matrix and distro coverage live in
[`ebpf-feasibility.md`](ebpf-feasibility.md). eBPF is **Linux-only**; on
macOS/Windows, run the agent inside a Linux VM.

On startup the agent logs a **capability probe** (BTF / ring buffer / CAP_BPF /
compiled-in) and the mode it chose, so an unsupported host is a *decided, visible*
state — never a silent failure.

## Kernel-matrix CI

Static checks aren't enough for kernel code, so the `ebpf-kernel-matrix` CI job
actually **loads and attaches** every BPF program on real LTS kernels (LTS —
long-term support — the kernel lines distros actually ship; the images are
digest-pinned, i.e. referenced by cryptographic hash rather than a floating tag)
under **QEMU** — a machine emulator that boots a complete kernel inside an
ephemeral VM — via `vimto`, a small tool that runs a Go test suite inside such a
booted kernel. It runs the live smoke: l4flow tracepoint attach, sslsniff uprobe
attach (consented + scoped), one full agent flush cycle, with object-digest
verification on the load path. The images are `ghcr.io/cilium/ci-kernels`.

The matrix is **5.15** and **6.6** on x86_64, **6.6 on arm64**, plus a **hardened
entry** on x86_64 that raises kernel lockdown to **integrity** inside the
ephemeral VM (`TestLiveHardenedLockdownIntegrity`, gated on
`PROBECTL_TEST_SET_LOCKDOWN=integrity`) and proves load+attach still works there
while the probe reports the mode truthfully (confidentiality is the blocking mode;
the test skips loudly if the CI kernel lacks the lockdown LSM — a secure-boot
distro-kernel image is the remaining infrastructure gap).

One arch nuance worth knowing: the live QEMU boot needs KVM (the kernel's
hardware-assisted virtualization, which lets the VM run at near-native speed
instead of instruction-by-instruction emulation) for usable speed. Both x86_64 and
arm64 now run the **full live load+attach** path under KVM. The arm64 row targets a
self-hosted Linux/ARM64 runner with the custom `kvm` label; if `/dev/kvm` is
missing, the job fails instead of falling back to compile-only coverage. Treat
arm64 eBPF releases as live-load-proven only when that matrix row is green. Bump
the matrix when adopting a new LTS.

## Building

| Build | Command | Source | Needs |
|---|---|---|---|
| Default (any OS) | `make build` | FixtureSource / stub | nothing extra |
| Live eBPF (Linux) | `make ebpf-agent` | CO-RE loader | clang + bpftool + a BTF kernel (libbpf BPF headers are vendored in-repo under `internal/ebpf/bpf/headers/` — no `libbpf-dev` needed) |

**The shipped artifacts are live builds.** Fixture mode is dev/test-only. The
shipped agent image is the live `-tags ebpf` build: `deploy/docker/Dockerfile.ebpf`
runs the same `bpf2go` + digest-generation path (`bpf2go` is the `cilium/ebpf`
generator that compiles the C with `clang` and embeds the resulting BPF object
into Go source). The downloadable `probectl-ebpf-agent_linux_{amd64,arm64}`
binaries use the same generator path through `scripts/build-release-binaries.sh`
instead of the plain cross-compile loop, and the deb/rpm package job checks that
same binary before wrapping it. The CI/release gates **fail unless Go build
metadata records `-tags=ebpf`** — so a fixture-only image, binary, or package
cannot ship unnoticed.

**Trust boundary (decided):** operator-supplied BPF objects are deliberately **not
supported**. The chain is: source → `bpf2go` (pinned `clang`) → objects **embedded
in the binary** → a SHA-256 manifest baked at the same build → `VerifyObjectDigest`
before any kernel load → the binary/image **cosign-signed** at release (cosign is
the Sigstore artifact-signing tool — the signature proves the artifact came from
this repo's release workflow). The release signature covers the objects +
manifest *together*, so a swapped object can't ride a signed binary. A static gate (`TestNoOperatorSuppliedBPFObjectPath`) trips if
anyone adds a filesystem/env object-load path.

The live build regenerates `vmlinux.h` (a generated header containing the
kernel's type definitions, dumped from its BTF) from the running kernel, runs
`bpf2go`, and writes the SHA-256 manifest (`gendigests` → `bpf_digests_ebpf.go`)
that the loaders verify before **any** kernel load — a tampered or stale object
refuses to load. The `cilium/ebpf` loader dependency is already pinned in
`go.mod`; only the `-tags ebpf` files import it, so the default build never
compiles or links it. On the build host:

```sh
make ebpf-agent                    # bpftool + bpf2go + go build -tags ebpf
```

A single wrapper, `internal/ebpf/gen_bpf.sh`, is the one place the `bpf2go` flags
and the arch-compat shim live — `make ebpf-agent`, the Dockerfile, the CI jobs, and
`go generate` all route through it, so a build change touches one file instead of
drifting across many. Release downloads add one more wrapper around the same path:

```sh
VERSION=v0.1.0 COMMIT="$(git rev-parse HEAD)" bash scripts/build-release-binaries.sh
go version -m dist/probectl-ebpf-agent_v0.1.0_linux_amd64 | grep -E 'build[[:space:]]+-tags=.*ebpf'
```

The generated bindings (`l4flow_bpfel.go`, `bpf/vmlinux.h`) carry
`//go:build ebpf`, are git-ignored, and are regenerated per build.

## Installing

If this is your first probectl producer, start with
[`getting-started.md`](getting-started.md) (the control-plane + bus bring-up) and
[`deploying-agents.md`](deploying-agents.md) (the per-producer deployment
journeys, including this agent) — you're done when flow batches show up
downstream, not when the unit reports active. The sections below are the
agent-specific contract.

### Kubernetes

The `deploy/helm/probectl-agent` chart deploys the agent as a **DaemonSet** (one
pod per node — host-level capture needs an agent on every host) with the
privilege contract declared in the manifest: drop **all** capabilities and add
back only `CAP_BPF` / `CAP_PERFMON`. `capabilityMode: legacy` renders
`CAP_SYS_ADMIN` only with the explicit `legacyKernelRingBufferAck` acknowledgement
after the runtime probe has confirmed BTF + BPF ring-buffer support; it is not a
generic `<5.8` escape hatch. The chart also declares a **seccomp** profile (a
kernel syscall filter — the process may invoke only the listed system calls;
`RuntimeDefault`, or point `seccomp.type: Localhost` at the installed
default-deny profile for tighter filtering), read-only root, the BTF host mount,
and resource limits. Rendering **fails closed**: no `tenantID`, L7 capture without
`l7Capture.scope`, or plaintext kafka without the explicit `bus.allowPlaintext`,
refuses to template. CI helm-lints, hardening-asserts, and kubeconform-validates
the chart on every run.

Health probes are listenerless by default. The agent writes `live.json` and
`ready.json` under `health.stateDir`, and the DaemonSet uses exec probes that run
`/usr/local/bin/app healthcheck --live|--ready` inside the container. The
compatibility HTTP mode (`/healthz` and `/readyz` on `health.port`) is fenced
behind `health.mode=http` plus `health.allowPlaintextHTTP=true`; the default chart
does not open port 9090.

The chart also renders the cluster-side Kyverno image-integrity policy by
default. Think of it as the second lock on this privileged pod: Helm requires a
digest-pinned image reference, and admission then requires that digest plus the
keyless cosign signature from the `release.yml` tag workflow. Kyverno must
already be installed. If a dev cluster uses a replacement admission controller,
set `admission.imageIntegrity.enabled=false` only with a non-empty
`admission.imageIntegrity.acceptedRisk` note.

The chart also renders `probectl-agent-capability-posture` (EBPF-007), a
Kyverno background/audit policy for capability drift. In ELI5 terms: the
DaemonSet is allowed to carry the modern `BPF` + `PERFMON` keys, and the policy
reports when a pod drops the `ALL` baseline, runs the explicit legacy
`SYS_ADMIN` break-glass path, or gains any extra key such as `NET_ADMIN`. Those
policy reports are the operational alert surface for capability posture; the
default is Audit so the documented legacy exception remains human-gated instead
of silently blocked.

```sh
helm install probectl-agent deploy/helm/probectl-agent \
  --set tenantID=acme \
  --set 'bus.brokers={kafka.probectl.svc:9093}' \
  --set bus.tls.existingSecret=probectl-bus-tls \
  --set-string image.tag='0.4.0@sha256:<digest>'
```

(In Kubernetes the container runs as uid 0 with everything dropped except the
minimal pair — Kubernetes grants added capabilities to root only, with no ambient-
capability support. The VM unit below instead runs **fully non-root** via ambient
capabilities — the Linux mechanism that lets a systemd service hand specific
capabilities to a non-root process.)

### VM / bare metal

`deploy/agent/install.sh` installs a local binary (air-gap friendly — downloads
nothing, never self-updates), creates the `probectl-agent` system user, installs
the hardened systemd unit, and writes a fail-closed sample config:

```sh
sudo deploy/agent/install.sh ./bin/probectl-ebpf-agent
$EDITOR /etc/probectl/ebpf-agent.yaml   # set tenant_id + brokers
sudo systemctl start probectl-ebpf-agent
```

### Hardened runtime profile

Run the agent with the **minimal capability set** and the shipped seccomp profile
— see [`deploy/agent/`](../deploy/agent/README.md): `CAP_BPF` + `CAP_PERFMON` on
kernels ≥ 5.8 (`CAP_SYS_ADMIN` only as an explicit legacy exception after the
runtime probe confirms BTF + ring-buffer support), `LimitMEMLOCK`, no root,
default-deny seccomp (`deploy/agent/seccomp.json`), plus a hardened systemd unit
and container/K8s `securityContext` examples.

## Running

```sh
# No-kernel / CI / macOS: replay recorded flows.
PROBECTL_EBPF_TENANT_ID=<uuid> PROBECTL_EBPF_FIXTURE_PATH=flows.json probectl-ebpf-agent

# Live (Linux, built with -tags ebpf, as root or with CAP_BPF+CAP_PERFMON):
probectl-ebpf-agent -config /etc/probectl/ebpf-agent.yaml
```

Example config:
[`deploy/agent/probectl-ebpf-agent.example.yml`](../deploy/agent/probectl-ebpf-agent.example.yml).

## Configuration keys

See [`configuration.md`](configuration.md#ebpf-host-agent) for the full
`PROBECTL_EBPF_*` table.

## Scope and follow-ups

In scope today: the agent, IPv4/IPv6 L3/L4 capture with byte/packet counters, the
service map, **L7 parsing (HTTP/1.1+2, gRPC, DNS, Kafka) with TLS-uprobe plaintext
capture**, OTel emit, and the kernel/uprobe matrix. On the consuming side, the
control plane already drains `probectl.ebpf.flows` on three independent,
tenant-verified consumer groups: the **topology** view (service edges feed the
graph), **segmentation validation** (declared policy vs observed traffic), and
**NDR detection**. Natural follow-ups (out of scope here): the **5-tuple↔SSL
correlation** and the **Go-TLS** capture path; and raw-flow retention in
ClickHouse with a flow-level query API. Detection, segmentation validation, TLS
posture, and cost all build on this layer.
