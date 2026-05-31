# deploy/docker/

Container build assets.

`Dockerfile` is a single, multi-stage, multi-arch build that produces any one of
netctl's Go binaries, selected with the `COMPONENT` build arg. The build context
is the **repository root** so the Go module is available.

```sh
# Build one component for the host arch (via the Makefile):
make images                                   # builds all components, multi-arch

# Or directly:
docker build -f deploy/docker/Dockerfile --build-arg COMPONENT=netctl-control -t netctl-control:dev .
```

Images are built for `linux/amd64` and `linux/arm64` and tagged `<version>` and
`latest` (CLAUDE.md §4). Multi-arch builds use Docker Buildx + QEMU (see CI).
