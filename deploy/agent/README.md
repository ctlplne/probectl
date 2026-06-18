# Hardened run profiles for probectl-ebpf-agent

This directory holds the deployment artifacts that run the eBPF host agent
under tight privilege limits — a **systemd unit** (the service file telling
Linux's init system how to run *and confine* the process), a **seccomp
profile** (a kernel-enforced allowlist of the system calls the process may
make), a VM installer, and example configs. (For the catalog of every
agent/collector and which one to deploy when, see
[`docs/deploying-agents.md`](../../docs/deploying-agents.md).)

The eBPF agent is **observe-only** (the CI gate refuses enforcing program
types), but it loads kernel programs — so it runs with the smallest
**capability** set the kernel allows (capabilities are the named slivers Linux
splits root's power into; holding two slivers is not root), a default-deny
seccomp profile, and no root. The principle: a process that talks to the
kernel's tracing machinery should be able to do *exactly* that and nothing
else — not mount filesystems, not load modules, not inspect other processes.

## What's in this directory

| File | What it is |
| ---- | ---------- |
| `probectl-ebpf-agent.service` | hardened systemd unit (ambient `CAP_BPF`+`CAP_PERFMON`, syscall filter, namespace lockdown) |
| `seccomp.json` | default-deny (`EPERM`) syscall allowlist for the container runtime |
| `install.sh` | VM / bare-metal installer (creates the system user, installs the binary + unit + a fail-closed sample config) |
| `probectl-ebpf-agent.example.yml` | example config for the eBPF host/flow agent |
| `probectl-flow-agent.example.yml` | example config for the standalone NetFlow/IPFIX/sFlow collector |
| `probectl-device-agent.example.yml` | example config for the device-telemetry (SNMP/gNMI) agent |
| `probectl-agent.example.yml` | example config for the canary/synthetic agent |

## Capability matrix by kernel

| Kernel | Capabilities | Notes |
|---|---|---|
| **>= 5.8** (preferred) | `CAP_BPF` + `CAP_PERFMON` | the minimal pair: `bpf()` program/map ops + `perf_event_open` for uprobe/tracepoint attach. The agent needs nothing else — not `CAP_NET_ADMIN` (observe-only, no tc/XDP), not `CAP_SYS_PTRACE`, not root |
| **5.4 – 5.7** | `CAP_SYS_ADMIN` | pre-5.8 kernels gate `bpf()` behind SYS_ADMIN; upgrade when possible |
| any | `LimitMEMLOCK=infinity` (or a sized `RLIMIT_MEMLOCK`) | BPF maps + the ring buffer are locked memory (pinned in RAM, never swapped to disk) |

A BTF kernel (`/sys/kernel/btf/vmlinux`, >= 5.8 on all mainstream LTS
distros) is required for the CO-RE build — BTF is the kernel's embedded type
catalog, and CO-RE (*compile once, run everywhere*) builds read it to adapt
the compiled program to the running kernel. See the kernel-matrix CI job and
`docs/ebpf-agent.md`.

## systemd

Install `probectl-ebpf-agent.service` (this directory): minimal **ambient**
capabilities (granted directly to the non-root process at start — no setuid
binary, no root parent), `NoNewPrivileges`, a `@system-service`-based syscall
filter plus `bpf`/`perf_event_open` with mount/module/ptrace classes denied,
and filesystem/namespace lockdown. Create the `probectl-agent` system user.

`install.sh` verifies the binary's cosign keyless signature by default before it
copies or enables anything. Put `<binary>.sig` and `<binary>.pem` next to the
binary (or set `PROBECTL_COSIGN_SIG` / `PROBECTL_COSIGN_CERT`) and run:

```sh
sudo ./install.sh ./probectl-ebpf-agent ./probectl-ebpf-agent.example.yml
```

If an air-gapped site verifies the artifact out of band, the unverified install
path is explicit break-glass:

```sh
sudo env PROBECTL_UNVERIFIED_INSTALL_ACK=allow-unsigned-cap-bpf-code \
  ./install.sh --no-verify ./probectl-ebpf-agent ./probectl-ebpf-agent.example.yml
```

That command installs privileged host code, so keep the external verification
receipt with the change record.

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

## Kubernetes (DaemonSet securityContext)

**The supported artifact is the `deploy/helm/probectl-agent` chart** — it
declares this exact contract (plus the BTF mount, resource limits, and
fail-closed rendering) and is lint/hardening/kubeconform-gated in CI
(kubeconform validates the rendered manifests against the Kubernetes API
schema). The snippet below is the shape it renders; note Kubernetes grants
added capabilities to uid 0 only, so the chart runs the container as root with
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
no mount, no module loading, no ptrace, no reboot/kexec. Default-deny works
like a guest list, not a blocklist: a syscall that isn't named is refused no
matter how new or obscure it is, and the refusal is `EPERM` ("permission
denied", an error the caller sees) rather than killing the process — so an
unexpected call fails visibly instead of taking the agent down.
