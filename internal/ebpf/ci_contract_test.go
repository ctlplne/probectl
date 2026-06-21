// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"strings"
	"testing"
)

func TestKernelMatrixArm64RequiresKVMAndLiveAttach(t *testing.T) {
	ci := readDeployContractFile(t, ".github/workflows/ci.yml")
	for _, want := range []string{
		`kernel: "6.6-arm64"`,
		`runner: [self-hosted, Linux, ARM64, kvm]`,
		`go test -tags ebpf -exec`,
		`no /dev/kvm`,
		`exit 1`,
	} {
		if !strings.Contains(ci, want) {
			t.Fatalf("ci.yml missing arm64 live-kernel contract %q (EBPF-003)", want)
		}
	}
	for _, banned := range []string{
		"skipping the live kernel boot",
		"SKIP the live boot",
		"exit 0\n          fi\n          sudo chmod 0666 /dev/kvm",
		"arm64 BPF objects compiled+verified above",
	} {
		if strings.Contains(ci, banned) {
			t.Fatalf("ci.yml still allows arm64 live-kernel skip %q (EBPF-003)", banned)
		}
	}
}

func TestKernelMatrixDocsDoNotClaimArm64CompileOnly(t *testing.T) {
	for _, rel := range []string{
		"docs/ci-pipeline.md",
		"docs/development.md",
		"docs/ebpf-agent.md",
		"docs/security/agent-whitepaper.md",
	} {
		body := readDeployContractFile(t, rel)
		for _, banned := range []string{
			"skips the live boot",
			"skipped there",
			"compile/digest-tested, not CI live-load proven",
			"compiles + digest-verifies the arm64 objects but skips",
		} {
			if strings.Contains(body, banned) {
				t.Fatalf("%s still claims arm64 eBPF is compile-only: %q", rel, banned)
			}
		}
	}
}
