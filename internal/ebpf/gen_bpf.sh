#!/usr/bin/env bash
# gen_bpf.sh — single source of truth for compiling probectl's BPF objects.
#
# Called by `make ebpf-agent`, deploy/docker/Dockerfile.ebpf, the ci.yml eBPF
# jobs, and `go generate ./internal/ebpf/...`. Keeping ONE bpf2go invocation
# here — rather than five near-identical copies — is deliberate: the vendored
# -I/header flags and the arch_compat opt-out below live in exactly one place,
# so a build change touches one file instead of drifting across many.
#
# Precondition: internal/ebpf/bpf/vmlinux.h is already dumped from the build
# host's BTF. The caller does that (the bpftool invocation differs per env —
# e.g. ci.yml locates a linux-tools-generic binary), so this script does not.
#
# Usage: gen_bpf.sh [l4flow|sslsniff|all] [sslsniff_target_arch]
#   - selector defaults to "all"
#   - sslsniff_target_arch defaults to the host's $(go env GOARCH); the
#     Dockerfile cross-build passes ${TARGETARCH} explicitly.
set -euo pipefail
cd "$(dirname "$0")" # -> internal/ebpf

# Honor the Makefile's GO (pinned toolchain); default to `go` on PATH for
# `go generate` / the CI + Docker callers.
GO="${GO:-go}"

# SUPPLY-001: pin the BPF compiler. clang/llvm is the one floating input on the
# privileged eBPF build path — a distro-default `clang` drifts across rebuilds
# and breaks reproducibility of the U-014 BPF digests. Default to the pinned
# clang-14 (Debian bookworm's versioned package; the Dockerfile installs exactly
# that), overridable via CLANG for an operator on a different pinned toolchain.
CLANG="${CLANG:-clang-14}"
# Fall back to a bare `clang` only if the pinned one is genuinely absent (e.g. a
# dev box) — and say so, so a silent unpinned compile is visible.
if ! command -v "$CLANG" >/dev/null 2>&1; then
	echo "gen_bpf.sh: pinned $CLANG not found; falling back to unpinned 'clang' (reproducibility NOT guaranteed — install ${CLANG} or set CLANG)" >&2
	CLANG="clang"
fi

what="${1:-all}"
ssl_target="${2:-$("$GO" env GOARCH)}"

test -s bpf/vmlinux.h || {
	echo "gen_bpf.sh: bpf/vmlinux.h missing — dump it from /sys/kernel/btf/vmlinux first" >&2
	exit 1
}

# arch_compat.h shims arm64's `struct user_pt_regs` for builds whose vmlinux.h
# lacks it (x86 build host -> arm64 object). When the build host IS arm64, its
# own vmlinux.h ALREADY defines that struct, so the shim would redefine it and
# clang fails ("redefinition of 'struct user_pt_regs'"). Look at what vmlinux.h
# actually contains and tell the shim to step aside when the real struct is
# present — correct for native arm64, native amd64, and the x86->arm64
# cross-build with one rule, instead of guessing from the host arch.
compat=()
if grep -q 'struct user_pt_regs {' bpf/vmlinux.h; then
	compat=(-DPROBECTL_VMLINUX_HAS_USER_PT_REGS)
fi

b2g() { "$GO" run github.com/cilium/ebpf/cmd/bpf2go -cc "$CLANG" -tags ebpf -go-package ebpf "$@"; }

# l4flow: arch-neutral tracepoint program (no arch_compat.h, no per-arch object).
gen_l4flow() {
	b2g -target bpfel l4flow ./bpf/l4flow.bpf.c -- -I./bpf -I./bpf/headers
}
# sslsniff: uprobe program; register layout is per-arch, so it builds for the
# requested target arch and carries the arch_compat opt-out when applicable.
gen_sslsniff() {
	b2g -target "$ssl_target" sslsniff ./bpf/sslsniff.bpf.c -- -I./bpf -I./bpf/headers "${compat[@]}"
}

case "$what" in
l4flow) gen_l4flow ;;
sslsniff) gen_sslsniff ;;
all)
	gen_l4flow
	gen_sslsniff
	;;
*)
	echo "gen_bpf.sh: usage: gen_bpf.sh [l4flow|sslsniff|all] [sslsniff_target_arch]" >&2
	exit 2
	;;
esac
