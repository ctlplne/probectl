# deploy/docker/

Container build assets — the Dockerfiles that turn probectl's Go binaries into
images.

| File | What it builds |
| ---- | -------------- |
| `Dockerfile` | a single multi-stage, multi-arch build that produces **any one** of probectl's Go binaries, selected with the `COMPONENT` build arg (a distroless `nonroot` final image) |
| `Dockerfile.ebpf` | the **live** `probectl-ebpf-agent` image — same binary, but built with the eBPF CO-RE loader compiled in (`-tags ebpf`) instead of the fixture replayer |

Both builds use the **repository root** as the build context so the Go module is
available.

## Generic component image (`Dockerfile`)

`COMPONENT` names a directory under `cmd/` (e.g. `probectl-control`,
`probectl-agent`, `probectl-endpoint`, `probectl-flow-agent`,
`probectl-device-agent`, `probectl`).

```sh
# Build every component image, multi-arch, via the Makefile:
make images

# Or one component directly:
docker build -f deploy/docker/Dockerfile --build-arg COMPONENT=probectl-control -t probectl-control:dev .
```

Images target `linux/amd64` and `linux/arm64` and are tagged `<version>` and
`latest` (CLAUDE.md §4). Multi-arch builds use Docker Buildx + QEMU (see
`make images` and the release workflow).

## Live eBPF agent image (`Dockerfile.ebpf`)

The generic `Dockerfile` compiles plain Go, so `probectl-ebpf-agent` built that
way is the **fixture-only replayer** (the dev/test path that has no kernel
loader). The shipped agent must carry the live loader, so `Dockerfile.ebpf`
runs the same toolchain operators use (`make ebpf-agent`): `bpf2go` (clang)
compiles the BPF objects for both arches, then the Go build embeds them under
`-tags ebpf`. The build host needs a readable `/sys/kernel/btf/vmlinux`; the
deployment kernel is relocated at load time by CO-RE.

```sh
docker build -f deploy/docker/Dockerfile.ebpf -t probectl-ebpf-agent:dev .
```

The release workflow publishes `probectl-ebpf-agent` from this file (the rest of
the components from the generic `Dockerfile`); a CI job asserts the shipped
binary actually records the `ebpf` tag so a fixture image can't ship by mistake.
