#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-probectl-TBD
#
# Build the downloadable release binaries. The eBPF agent is special: a plain
# `go build ./cmd/probectl-ebpf-agent` links the fixture/stub source, so the
# release path must generate BPF objects and compile with `-tags ebpf` before
# the binary can be signed or packaged.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

GO="${GO:-go}"
VERSION="${VERSION:-${GITHUB_REF_NAME:-v0.0.0-dev}}"
COMMIT="${COMMIT:-${GITHUB_SHA:-$(git rev-parse --short=12 HEAD)}}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
DIST_DIR="${DIST_DIR:-dist}"
ARCHES="${ARCHES:-amd64 arm64}"
BINARIES="${BINARIES:-probectl-control probectl-agent probectl-ebpf-agent probectl-endpoint probectl-flow-agent probectl-device-agent probectl}"
BTF_PATH="${BTF_PATH:-/sys/kernel/btf/vmlinux}"
CLANG="${CLANG:-clang-14}"

ldflags="-s -w -X github.com/imfeelingtheagi/probectl/internal/version.Version=${VERSION} -X github.com/imfeelingtheagi/probectl/internal/version.Commit=${COMMIT} -X github.com/imfeelingtheagi/probectl/internal/version.Date=${DATE}"

find_bpftool() {
	local tool
	tool="$(find /usr/lib -path '*linux-tools*' -name bpftool -type f 2>/dev/null | sort -V | tail -n1)"
	if [ -n "$tool" ]; then
		printf '%s\n' "$tool"
		return
	fi
	if command -v bpftool >/dev/null 2>&1; then
		command -v bpftool
	fi
}

assert_ebpf_buildinfo() {
	local bin="$1"
	local info
	info="$("$GO" version -m "$bin")"
	printf '%s\n' "$info"
	if ! grep -Eq '\bbuild[[:space:]]+-tags=.*\bebpf\b' <<<"$info"; then
		echo "::error::${bin} was not built with -tags ebpf; refusing to release a fixture-only eBPF agent"
		exit 1
	fi
}

build_plain_binary() {
	local component="$1"
	local arch="$2"
	local out="$3"
	echo ">> ${component} linux/${arch}"
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 "$GO" build -trimpath \
		-ldflags "$ldflags" \
		-o "$out" "./cmd/${component}"
}

build_ebpf_binary() {
	local arch="$1"
	local out="$2"
	local bpftool
	echo ">> probectl-ebpf-agent linux/${arch} (-tags ebpf)"

	if ! command -v "$CLANG" >/dev/null 2>&1; then
		echo "::error::release eBPF binary build requires ${CLANG}; install the pinned toolchain before signing downloads"
		exit 1
	fi
	bpftool="$(find_bpftool)"
	if [ -z "$bpftool" ]; then
		echo "::error::release eBPF binary build requires bpftool (or linux-tools-generic)"
		exit 1
	fi
	if [ ! -s "$BTF_PATH" ]; then
		echo "::error::release eBPF binary build requires readable BTF at ${BTF_PATH}"
		exit 1
	fi

	"$bpftool" btf dump file "$BTF_PATH" format c > internal/ebpf/bpf/vmlinux.h
	(cd internal/ebpf && GO="$GO" CLANG="$CLANG" bash gen_bpf.sh all "$arch")
	(cd internal/ebpf && "$GO" run ./gendigests .)
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 "$GO" build -trimpath -tags ebpf \
		-ldflags "$ldflags" \
		-o "$out" ./cmd/probectl-ebpf-agent
	assert_ebpf_buildinfo "$out"
}

mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR/checksums.txt"

for arch in $ARCHES; do
	for component in $BINARIES; do
		out="${DIST_DIR}/${component}_${VERSION}_linux_${arch}"
		if [ "$component" = "probectl-ebpf-agent" ]; then
			build_ebpf_binary "$arch" "$out"
		else
			build_plain_binary "$component" "$arch" "$out"
		fi
	done
done

(cd "$DIST_DIR" && sha256sum probectl* > checksums.txt)
ls -la "$DIST_DIR"
