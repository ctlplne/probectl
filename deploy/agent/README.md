# Hardened run profiles for probectl-ebpf-agent (U-052)

The eBPF agent is **observe-only** (the CI gate refuses enforcing program
types), but it loads kernel programs — so it runs with the smallest
capability set the kernel allows, a default-deny seccomp profile, and no
root.

## Capability matrix by kernel

| Kernel | Capabilities | Notes |
|---|---|---|
| **>= 5.8** (preferred) | `CAP_BPF` + `CAP_PERFMON` | the minimal pair: `bpf()` program/map ops + `perf_event_open` for uprobe/tracepoint attach. The agent needs nothing else — not `CAP_NET_ADMIN` (observe-only, no tc/XDP), not `CAP_SYS_PTRACE`, not root |
| **5.4 – 5.7** | `CAP_SYS_ADMIN` | pre-5.8 kernels gate `bpf()` behind SYS_ADMIN; upgrade when possible |
| any | `LimitMEMLOCK=infinity` (or a sized `RLIMIT_MEMLOCK`) | BPF maps + the ring buffer are locked memory |

A BTF kernel (`/sys/kernel/btf/vmlinux`, >= 5.8 on all mainstream LTS
distros) is required for the CO-RE build — see the kernel-matrix CI job and
`docs/ebpf-agent.md`.

## systemd

Install `probectl-ebpf-agent.service` (this directory): minimal ambient
capabilities, `NoNewPrivileges`, a `@system-service`-based syscall filter
plus `bpf`/`perf_event_open` with mount/module/ptrace classes denied, and
filesystem/namespace lockdown. Create the `probectl-agent` system user.

## Containers (docker / compose)

```yaml
services:
  ebpf-agent:
    image: ghcr.io/imfeelingtheagi/probectl-ebpf-agent:<tag>
    security_opt:
      - no-new-privileges:true
      - seccomp=./deploy/agent/seccomp.json
    cap_drop: [ALL]
    cap_add: [BPF, PERFMON]        # kernel >= 5.8; use SYS_ADMIN on older kernels
    ulimits: { memlock: -1 }
    volumes:
      - /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro
```

## Kubernetes (DaemonSet securityContext — U-016 pairing)

**The supported artifact is the `deploy/helm/probectl-agent` chart** — it
declares this exact contract (plus the BTF mount, resource limits, and
fail-closed rendering) and is lint/hardening/kubeconform-gated in CI. The
snippet below is the shape it renders; note Kubernetes grants added
capabilities to uid 0 only, so the chart runs the container as root with
ALL dropped except the pair (the systemd unit achieves non-root via
ambient capabilities instead). For VM installs use `install.sh`.

```yaml
securityContext:
  runAsUser: 0   # k8s grants added caps to uid 0 only; ALL dropped below
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
    add: ["BPF", "PERFMON"]   # SYS_ADMIN only on kernels < 5.8
  seccompProfile:
    type: Localhost
    localhostProfile: probectl/seccomp.json   # install on each node
```

The seccomp profile (`seccomp.json`) is default-deny (`EPERM`): the
allowlist covers the Go runtime, `bpf`, `perf_event_open`, and socket I/O —
no mount, no module loading, no ptrace, no reboot/kexec.
