#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Run a command inside the pinned eBPF build toolchain stage. This keeps the
# kernel-loadable BPF object compiler path off mutable GitHub runner apt state.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

image="${PROBECTL_EBPF_TOOLCHAIN_IMAGE:-probectl-ebpf-toolchain:local}"
dockerfile="${PROBECTL_EBPF_TOOLCHAIN_DOCKERFILE:-deploy/docker/Dockerfile.ebpf}"
target="${PROBECTL_EBPF_TOOLCHAIN_TARGET:-ebpf-toolchain}"

docker build --target "$target" -f "$dockerfile" -t "$image" .

if [ "$#" -eq 0 ]; then
  set -- bash
fi

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$repo_root:/src" \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -w /src \
  -e GOCACHE=/tmp/probectl-go-cache \
  -e GOMODCACHE=/tmp/probectl-go-mod \
  -e GOFLAGS="${GOFLAGS:-}" \
  -e VERSION="${VERSION:-}" \
  -e COMMIT="${COMMIT:-}" \
  -e DATE="${DATE:-}" \
  -e PROBECTL_LICENSE_PUBKEYS_B64="${PROBECTL_LICENSE_PUBKEYS_B64:-}" \
  -e DIST_DIR="${DIST_DIR:-}" \
  -e ARCHES="${ARCHES:-}" \
  -e BINARIES="${BINARIES:-}" \
  -e GITHUB_REF_NAME="${GITHUB_REF_NAME:-}" \
  -e GITHUB_SHA="${GITHUB_SHA:-}" \
  "$image" "$@"
