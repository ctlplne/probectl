#!/usr/bin/env bash
# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.
#
# ebpf-kernel-lane.sh — run the ebpf-kernel-matrix live tests on a chosen
# kernel WITHOUT KVM, so a matrix failure reproduces on a laptop (macOS Docker
# Desktop included). It boots the kernel with the same vimto the CI job uses,
# under QEMU TCG (VIMTO_DISABLE_KVM=1), inside a Linux container on the host's
# own architecture. It is a reproduction lane, not a substitute for the CI job:
# the matrix still requires KVM.
#
# Usage: scripts/ebpf-kernel-lane.sh <kernel> [go test -run regex]
#   <kernel>  5.15 | 6.6 — the ci.yml matrix row (its digest-pinned image on an
#             amd64 host; the same ci-kernels series' arm64 image, pinned
#             below, on an arm64 host — the CI pins are amd64-only manifests,
#             so no arm64 image shares their digest) — or any full kernel image
#             reference vimto accepts.
#   regex     default 'TestLive'.
#
# PROBECTL_TEST_SET_LOCKDOWN is passed through, so the 6.6-lockdown row is
#   PROBECTL_TEST_SET_LOCKDOWN=integrity scripts/ebpf-kernel-lane.sh 6.6 TestLiveHardenedLockdown
#
# The BPF objects are generated first with the pinned toolchain
# (scripts/run-ebpf-toolchain.sh) unless they already exist; set GEN=1 to force.
# They are gitignored — delete them before committing.
#
# Measured on an arm64 Mac (10 CPU, Docker Desktop): a VM boot is ~6 s, the
# ING-24 pair (TestLiveInboundEdgeOrientation|TestLiveNonRootL4Attach) ~40 s.
# The VM gets one vCPU, like CI; the run is CPU-heavy for its duration.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

kernel="${1:?usage: ebpf-kernel-lane.sh <5.15|6.6|image-ref> [go test -run regex]}"
run="${2:-TestLive}"
name="${PROBECTL_EBPF_LANE_NAME:-probectl-ebpf-lane}"
# 256M, the size the CI matrix boots (DPR-402). vimto's default 128M is too
# small: the arm64 6.6 guest keeps only ~67 MB of it free, too little for the
# L4 ring buffer (map create: ENOMEM), and the amd64 5.15 guest was SIGKILLed
# during the non-root attach. PROBECTL_EBPF_LANE_MEMORY overrides it.
memory="${PROBECTL_EBPF_LANE_MEMORY:-size=256M}"
image="${PROBECTL_EBPF_LANE_IMAGE:-$name:local}"

case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*)
	echo "ebpf-kernel-lane: unsupported host architecture $(uname -m)" >&2
	exit 2
	;;
esac

# arm64 builds of the ci-kernels series the matrix pins (resolved from the
# multi-arch tags; the CI digests themselves are amd64-only manifests).
arm64_kernel() {
	case "$1" in
	5.15) echo "ghcr.io/cilium/ci-kernels@sha256:ad7209a490620801bb4e94a2956feaaf109de2d1cc358500e3d510d1c51d0b6d" ;; # 5.15.221
	6.6) echo "ghcr.io/cilium/ci-kernels@sha256:2a9cde64d0da32126d2c534da6701fa73df87503fa7f8fb74d0c1f011e263178" ;;  # 6.6.157
	*) return 1 ;;
	esac
}

# The matrix row's image, read from ci.yml so the lane can never drift from it.
ci_kernel() {
	awk -v row="$1" '
		$0 ~ "- kernel: \"" row "\"" { found = 1; next }
		found && /- kernel:/ { exit }
		found && /image:/ { print $2; exit }
	' .github/workflows/ci.yml
}

case "$kernel" in
*/* | *@sha256:*) kernel_image="$kernel" ;;
*)
	if [ "$arch" = arm64 ]; then
		kernel_image="$(arm64_kernel "$kernel")" || {
			echo "ebpf-kernel-lane: no arm64 image pinned for kernel row '$kernel' (rows: 5.15, 6.6); pass a full image reference" >&2
			exit 2
		}
	else
		kernel_image="$(ci_kernel "$kernel")"
		[ -n "$kernel_image" ] || {
			echo "ebpf-kernel-lane: ci.yml has no ebpf-kernel-matrix row '$kernel'" >&2
			exit 2
		}
	fi
	;;
esac

if [ "${GEN:-0}" = 1 ] || [ ! -s internal/ebpf/l4flow_bpfel.o ] || [ ! -s internal/ebpf/bpf_digests_ebpf.go ]; then
	bash scripts/run-ebpf-toolchain.sh bash -c '
		set -euo pipefail
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/ebpf/bpf/vmlinux.h
		(cd internal/ebpf && bash gen_bpf.sh all)
		(cd internal/ebpf && go run ./gendigests .)
	'
fi

# The lane image: the repo's pinned Go, QEMU for the host arch, iproute2 (vimto
# brings lo up with `ip`), util-linux (TestLiveNonRootL4Attach needs unshare and
# setpriv) and the vimto the CI job installs.
#
# arm64 TCG: `-cpu max` emulates pointer authentication with the QARMA5 cipher,
# which makes every guest instruction fetch crawl; the shim swaps in the IMPDEF
# algorithm, which is identical from the guest's point of view.
docker build -q -t "$image" - <<'EOF' >/dev/null
FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends qemu-system-arm qemu-system-x86 iproute2 util-linux \
 && rm -rf /var/lib/apt/lists/*
RUN CGO_ENABLED=0 go install lmb.io/vimto@v0.4.0
RUN printf '%s\n' '#!/bin/sh' \
      'n=$#; i=0; prev=' \
      'while [ $i -lt $n ]; do a=$1; shift; if [ "$prev" = -cpu ] && [ "$a" = max ]; then a=max,pauth-impdef=on; fi; set -- "$@" "$a"; prev=$a; i=$((i+1)); done' \
      'exec /usr/bin/qemu-system-aarch64 "$@"' > /usr/local/bin/qemu-system-aarch64 \
 && chmod 0755 /usr/local/bin/qemu-system-aarch64
EOF

echo "ebpf-kernel-lane: $arch host, kernel $kernel_image, memory $memory, -run '$run' (QEMU TCG, no KVM)" >&2
# --init: vimto treats PID 1 as the guest init, so it must not be PID 1 here.
exec docker run --rm --init --name "$name-$$" \
	-v "$repo_root:/src" -w /src \
	-v "$name-cache:/root/.cache" \
	-v "$name-gomod:/go/pkg/mod" \
	-e VIMTO_DISABLE_KVM=1 -e CGO_ENABLED=0 \
	-e PROBECTL_TEST_SET_LOCKDOWN \
	"$image" \
	go test -tags ebpf -exec "vimto -memory $memory -kernel $kernel_image -sudo exec --" -run "$run" -count=1 -v ./internal/ebpf/
