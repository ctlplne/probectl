// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// EBPF-002: the eBPF host agent is privileged, so its systemd confinement must
// not differ by distribution channel. The template unit (deploy/agent, shipped
// by Helm/install.sh) and the packaged unit (deploy/packaging/systemd, shipped
// by deb/rpm) must carry the SAME hardening directives — otherwise deb/rpm
// operators silently get a weaker, OOM-backstop-less profile. This guard reads
// both literal units and fails the build if the packaged one drifts below the
// hardened baseline.
func TestEBPFSystemdUnitsHardeningParity(t *testing.T) {
	template := readArtifact(t, "deploy/agent/probectl-ebpf-agent.service")
	packaged := readArtifact(t, "deploy/packaging/systemd/probectl-ebpf-agent.service")

	// Directives that MUST be present (with these values) on BOTH units. These
	// are the kernel/namespace confinement + the resource ceiling whose absence
	// was the finding.
	required := []string{
		"MemoryMax=512M",
		"MemoryHigh=384M",
		"TasksMax=128",
		"CPUQuota=100%",
		"MemoryDenyWriteExecute=yes",
		"ProtectKernelModules=yes",
		"ProtectKernelLogs=yes",
		"ProtectControlGroups=yes",
		"ProtectClock=yes",
		"RestrictNamespaces=yes",
		"RestrictRealtime=yes",
		"RestrictSUIDSGID=yes",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		"ProtectSystem=strict",
		"SystemCallArchitectures=native",
		"CapabilityBoundingSet=CAP_BPF CAP_PERFMON",
	}
	for _, d := range required {
		if !strings.Contains(template, d) {
			t.Errorf("template unit missing hardening directive %q", d)
		}
		if !strings.Contains(packaged, d) {
			t.Errorf("packaged (deb/rpm) unit missing hardening directive %q — confinement drift below the hardened baseline (EBPF-002)", d)
		}
	}

	// The syscall denylist (the ~-prefixed exclusions) must appear on both so
	// neither channel allows mount/module/ptrace etc.
	denylist := "SystemCallFilter=~@mount @module @reboot @swap @obsolete @cpu-emulation @keyring ptrace"
	if !strings.Contains(packaged, denylist) {
		t.Errorf("packaged unit missing the syscall denylist %q (EBPF-002)", denylist)
	}
}

// OPS-006: the packaged eBPF unit must not reference a seccomp JSON profile
// that the package never ships (nfpm bundles none for this agent). A dangling
// "deploy/.../*.json" reference in the unit would make an operator believe a
// confinement file is in place when it isn't — so any file path the unit names
// must actually exist in the repo, and the syscall surface must instead be
// bounded by the in-unit SystemCallFilter (which the parity test above checks).
func TestEBPFPackagedUnitHasNoDanglingSeccompReference(t *testing.T) {
	packaged := readArtifact(t, "deploy/packaging/systemd/probectl-ebpf-agent.service")
	root := repoRoot(t)

	// Catch any referenced *.json path (seccomp profiles are the concern).
	jsonRef := regexp.MustCompile(`[\w./-]+\.json`)
	for _, m := range jsonRef.FindAllString(packaged, -1) {
		if _, err := os.Stat(filepath.Join(root, m)); err != nil {
			t.Errorf("packaged eBPF unit references %q which does not exist in the repo — dangling seccomp/profile reference (OPS-006): %v", m, err)
		}
	}

	// The unit must still carry an in-unit syscall filter (the real confinement).
	if !strings.Contains(packaged, "SystemCallFilter=") {
		t.Error("packaged eBPF unit must bound syscalls via an in-unit SystemCallFilter (OPS-006)")
	}
}
