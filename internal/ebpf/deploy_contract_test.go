// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRootForDeployContract(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate go.mod from test working directory")
		}
		dir = parent
	}
}

func readDeployContractFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRootForDeployContract(t), rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestAgentHelmL7CaptureRendersRequiredScope(t *testing.T) {
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	configmap := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/configmap.yaml")
	schema := readDeployContractFile(t, "deploy/helm/probectl-agent/values.schema.json")

	for _, want := range []string{
		"scope: []",
		"redaction: headers",
		"kernelWindow: 1024",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing L7 capture knob %q (EBPF-002)", want)
		}
	}
	for _, want := range []string{
		"l7Capture.scope is required when l7Capture.enabled=true",
		"l7Capture.consentTenant is required when l7Capture.enabled=true",
		"l7_capture_scope:",
		"l7_capture_redaction:",
		"l7_capture_kernel_window:",
	} {
		if !strings.Contains(configmap, want) {
			t.Errorf("agent ConfigMap template missing L7 fail-closed/rendering contract %q (EBPF-002)", want)
		}
	}
	for _, want := range []string{
		"\"l7Capture\"",
		"\"scope\"",
		"pid:[0-9]+|exe:/.*|cgroup:/.*",
		"\"redaction\"",
		"\"kernelWindow\"",
	} {
		if !strings.Contains(schema, want) {
			t.Errorf("agent values.schema.json missing L7 schema contract %q (EBPF-002)", want)
		}
	}
}

func TestAgentLegacyCapabilityModeIsFenced(t *testing.T) {
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	daemonset := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/daemonset.yaml")
	notes := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/NOTES.txt")

	for _, want := range []string{
		"legacyKernelRingBufferAck: \"\"",
		"Generic <5.8 kernels remain",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing legacy capability fence %q (EBPF-004)", want)
		}
	}
	for _, want := range []string{
		"legacyKernelRingBufferAck",
		"i-confirm-runtime-ring-buffer-support",
		"generic <5.8 kernels are unsupported",
		"add: [\"SYS_ADMIN\"]",
	} {
		if !strings.Contains(daemonset, want) {
			t.Errorf("agent DaemonSet missing fenced legacy capability contract %q (EBPF-004)", want)
		}
	}
	if !strings.Contains(notes, "explicit legacy break-glass") {
		t.Errorf("agent NOTES must describe legacy SYS_ADMIN as explicit break-glass (EBPF-004)")
	}

	for _, rel := range []string{
		"deploy/helm/probectl-agent/Chart.yaml",
		"deploy/helm/probectl-agent/values.yaml",
		"deploy/helm/probectl-agent/templates/daemonset.yaml",
		"deploy/helm/probectl-agent/templates/NOTES.txt",
		"deploy/agent/README.md",
		"deploy/agent/probectl-ebpf-agent.service",
		"deploy/agent/install.sh",
		"docs/ebpf-agent.md",
	} {
		body := readDeployContractFile(t, rel)
		for _, banned := range []string{
			"5.4–5.7: CAP_SYS_ADMIN",
			"5.4-5.7: CAP_SYS_ADMIN",
			"kernels 5.4–5.7: CAP_SYS_ADMIN",
			"kernels 5.4-5.7: CAP_SYS_ADMIN",
			"use SYS_ADMIN on older kernels",
			"SYS_ADMIN only on kernels < 5.8",
			"CAP_SYS_ADMIN only for pre-5.8 kernels",
			"CAP_SYS_ADMIN only as the pre-5.8 fallback",
			"replace both with CAP_SYS_ADMIN",
			"set `capabilityMode: legacy` for 5.4",
		} {
			if strings.Contains(body, banned) {
				t.Errorf("%s still carries stale broad SYS_ADMIN guidance %q (EBPF-004)", rel, banned)
			}
		}
	}
}

func TestAgentDocsMentionNonStandardSecretHeaderRedaction(t *testing.T) {
	doc := readDeployContractFile(t, "docs/ebpf-agent.md")
	for _, want := range []string{
		"X-API-Key",
		"X-Amz-Security-Token",
		"custom `*Token*`",
		"TestRedactPayloadZeroesNonStandardSecretHeaders",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/ebpf-agent.md missing non-standard secret header redaction detail %q (EBPF-003)", want)
		}
	}
}
