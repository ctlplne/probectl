# deploy/docker/

Container build assets — the Dockerfiles that turn probectl's Go binaries into
images. A **Dockerfile** is the recipe `docker build` follows; the shipping
mechanics around it (tags, registries, multi-arch pushes) live in the Makefile
and the release workflow, so these two files are the single source of truth for
*what is inside an image*.

| File | What it builds |
| ---- | -------------- |
| `Dockerfile` | a single multi-stage, multi-arch build that produces **any one** of probectl's Go binaries, selected with the `COMPONENT` build arg (a distroless `nonroot` final image) |
| `Dockerfile.ebpf` | the **live** `probectl-ebpf-agent` image — same binary, but built with the eBPF CO-RE loader compiled in (`-tags ebpf`) instead of the fixture replayer |

Both builds use the **repository root** as the build context — the build
context being the set of files Docker is allowed to read while building. The
compile needs `go.mod` and all of `internal/`, so the context must be the whole
repo, not `deploy/docker/`.

## Generic component image (`Dockerfile`)

`COMPONENT` names a directory under `cmd/` (e.g. `probectl-control`,
`probectl-agent`, `probectl-endpoint`, `probectl-flow-agent`,
`probectl-device-agent`, `probectl`).

One mold, many castings: the build is **multi-stage** — a full Go-toolchain
stage compiles `cmd/<COMPONENT>` into one static binary, then only that binary
is copied into a **distroless** final stage (a base image with no shell and no
package manager — nothing an attacker could pivot with), which runs as the
unprivileged `nonroot` user. Swapping `COMPONENT` swaps the casting; the mold —
and therefore the size and security posture of every component image — stays
identical. That is also why the eBPF agent needs its own Dockerfile below: it
is the one binary whose build step differs.

```sh
# Build every component image, multi-arch, via the Makefile:
make images

# Or one component directly:
docker build -f deploy/docker/Dockerfile --build-arg COMPONENT=probectl-control -t probectl-control:dev .
```

Images target `linux/amd64` and `linux/arm64` and are tagged `<version>` and
`latest`. Multi-arch builds use Docker Buildx + QEMU (see `make images` and the
release workflow): Buildx is Docker's multi-platform builder, and QEMU supplies
CPU emulation for any step that must *execute* foreign-architecture code — the
Go stage itself cross-compiles natively (`CGO_ENABLED=0`), so the compile never
pays the emulation tax.

## Live eBPF agent image (`Dockerfile.ebpf`)

The generic `Dockerfile` compiles plain Go, so `probectl-ebpf-agent` built that
way is the **fixture-only replayer** (the dev/test path that has no kernel
loader). The shipped agent must carry the live loader, so `Dockerfile.ebpf`
runs the same toolchain operators use (`make ebpf-agent`): `bpf2go` (clang)
compiles the BPF objects for both arches, then the Go build embeds them under
`-tags ebpf`. (`bpf2go` is the cilium/ebpf code generator — it drives `clang`
over the C BPF source and embeds the compiled objects into the Go binary, so
the final image still has no compiler in it.) The build host needs a readable
`/sys/kernel/btf/vmlinux`; the deployment kernel is relocated at load time by
CO-RE. **BTF** is the kernel's embedded type catalog, and **CO-RE** — *compile
once, run everywhere* — means the embedded objects carry relocation info and
adapt themselves to whatever kernel they are loaded on: the build host's BTF is
read once at compile time, and each deployment kernel's BTF is read again at
load time.

```sh
docker build -f deploy/docker/Dockerfile.ebpf -t probectl-ebpf-agent:dev .
```

The release workflow publishes `probectl-ebpf-agent` from this file, and the
other six components — `probectl-control`, `probectl-agent`,
`probectl-endpoint`, `probectl-flow-agent`, `probectl-device-agent`, and
`probectl` — from the generic `Dockerfile`. A CI job asserts the shipped eBPF
binary actually records the `ebpf` build tag so a fixture image can't ship by
mistake.
