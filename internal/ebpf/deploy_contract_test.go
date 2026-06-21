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

func TestAgentHelmImageIntegrityAdmissionIsFailClosed(t *testing.T) {
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	policy := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/image-integrity-policy.yaml")
	standalone := readDeployContractFile(t, "deploy/admission/probectl-agent-image-integrity.kyverno.yaml")
	hardening := readDeployContractFile(t, "scripts/check_helm_hardening.sh")
	helmDoc := readDeployContractFile(t, "deploy/helm/README.md")
	admissionDoc := readDeployContractFile(t, "deploy/admission/README.md")

	for _, want := range []string{
		"imageIntegrity:",
		"enabled: true",
		"acceptedRisk: \"\"",
		"validationFailureAction: Enforce",
		"Audit is allowed only when",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing image-integrity admission contract %q (RED-003)", want)
		}
	}
	for _, want := range []string{
		"validationFailureAction must be Enforce",
		"acceptedRisk names the replacement control",
		"apiVersion: kyverno.io/v1",
		"kind: ClusterPolicy",
		"verifyImages:",
		"required: true",
		"verifyDigest: true",
		"subjectRegExp:",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("agent image-integrity template missing fail-closed contract %q (RED-003)", want)
		}
	}
	for _, want := range []string{
		"kind: ClusterPolicy",
		"verifyImages:",
		"required: true",
		"verifyDigest: true",
		"release\\.yml@refs/tags",
	} {
		if !strings.Contains(standalone, want) {
			t.Errorf("standalone admission policy missing verifier contract %q (RED-003)", want)
		}
	}
	for _, want := range []string{
		"non-enforcing image-integrity admission",
		"validationFailureAction=Audit",
		"admission.imageIntegrity.acceptedRisk",
		"kind: ClusterPolicy",
		"validationFailureAction: Enforce",
	} {
		if !strings.Contains(hardening, want) {
			t.Errorf("helm hardening gate missing image-integrity admission proof %q (RED-003)", want)
		}
	}
	for _, doc := range []struct {
		path string
		body string
	}{
		{path: "deploy/helm/README.md", body: helmDoc},
		{path: "deploy/admission/README.md", body: admissionDoc},
	} {
		for _, want := range []string{
			"Kyverno",
			"ClusterPolicy",
			"acceptedRisk",
			"fail closed",
		} {
			if !strings.Contains(doc.body, want) {
				t.Errorf("%s missing image-integrity admission documentation %q (RED-003)", doc.path, want)
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

func TestEBPFCaptureFollowupContract(t *testing.T) {
	agentDoc := readDeployContractFile(t, "docs/ebpf-agent.md")
	feasibility := readDeployContractFile(t, "docs/ebpf-feasibility.md")
	l4 := readDeployContractFile(t, "internal/ebpf/bpf/l4flow.bpf.c")
	decoder := readDeployContractFile(t, "internal/ebpf/l4event.go")
	policyTest := readDeployContractFile(t, "internal/ebpf/l7policy_test.go")

	for _, stale := range []string{
		"IPv4 only today",
		"IPv6 as planned",
		"IPv6 capture is planned",
		"ctx->family != AF_INET) {",
	} {
		for _, doc := range []struct {
			path string
			body string
		}{
			{path: "docs/ebpf-agent.md", body: agentDoc},
			{path: "internal/ebpf/bpf/l4flow.bpf.c", body: l4},
		} {
			if strings.Contains(doc.body, stale) {
				t.Errorf("%s still carries stale IPv4-only capture wording/code %q (TRACE-OMIT-F11)", doc.path, stale)
			}
		}
	}
	for _, want := range []string{
		"AF_INET6",
		"saddr_v6",
		"daddr_v6",
	} {
		if !strings.Contains(l4, want) {
			t.Errorf("l4flow.bpf.c missing IPv6 capture contract %q (TRACE-OMIT-F11)", want)
		}
	}
	for _, want := range []string{
		"l4FamilyIPv6",
		"NetworkIPv6",
		"netip.AddrFrom16",
	} {
		if !strings.Contains(decoder, want) {
			t.Errorf("l4event.go missing IPv6 decode contract %q (TRACE-OMIT-F11)", want)
		}
	}
	for _, want := range []string{
		"`l4flow` captures IPv4 and IPv6 TCP sockets",
		"`filtered_non_ipv4_total` flush field",
		"Go programs don't use libssl",
		"separate strategy",
	} {
		if !strings.Contains(agentDoc, want) {
			t.Errorf("docs/ebpf-agent.md missing capture limitation contract %q (TRACE-OMIT-F11)", want)
		}
	}
	for _, want := range []string{
		"Go-TLS as an explicitly-scoped",
		"separately-tested module",
		"ret-offset disassembly + goroutine tracking",
		"socket-layer",
		"plaintext L7",
	} {
		if !strings.Contains(feasibility, want) {
			t.Errorf("docs/ebpf-feasibility.md missing Go-TLS strategy contract %q (TRACE-OMIT-F11)", want)
		}
	}
	for _, want := range []string{
		"TestRedactPayloadZeroesSensitiveHeaderValues",
		"TestRedactPayloadZeroesNonStandardSecretHeaders",
		"TestRedactSensitiveHeaderResponseSetCookie",
	} {
		if !strings.Contains(policyTest, want) {
			t.Errorf("l7policy_test.go missing redaction regression %q (TRACE-OMIT-F11)", want)
		}
	}
}
