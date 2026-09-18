// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ebpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		"ringBufferBytes: 16777216",
		"identityHeaderFragments: []",
		"hashAllHeaderValues: false",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing L7 capture knob %q (EBPF-002)", want)
		}
	}
	for _, want := range []string{
		"l7Capture.scope is required when l7Capture.enabled=true",
		"l7Capture.consentTenant is required when l7Capture.enabled=true",
		"ring_buffer_bytes:",
		"l7_capture_scope:",
		"l7_capture_redaction:",
		"l7_capture_kernel_window:",
		"l7_ring_buffer_bytes:",
		"l7_capture_identity_header_fragments:",
		"l7_capture_hash_all_header_values:",
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
		"\"ringBufferBytes\"",
		"\"identityHeaderFragments\"",
		"\"hashAllHeaderValues\"",
	} {
		if !strings.Contains(schema, want) {
			t.Errorf("agent values.schema.json missing L7 schema contract %q (EBPF-002)", want)
		}
	}
}

func TestGeneratedEBPFConfigsDeclareSchemaVersion(t *testing.T) {
	configmap := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/configmap.yaml")
	installer := readDeployContractFile(t, "deploy/agent/install.sh")
	e2e := readDeployContractFile(t, "test/e2e/e2e_test.go")

	for _, tt := range []struct {
		name string
		body string
	}{
		{name: "helm ConfigMap", body: configmap},
		{name: "systemd installer sample", body: installer},
		{name: "e2e fixture config", body: e2e},
	} {
		if !strings.Contains(tt.body, "apiVersion: "+ConfigAPIVersion) &&
			!strings.Contains(tt.body, "schema_version: 1") {
			t.Fatalf("%s must emit apiVersion %q or schema_version: 1", tt.name, ConfigAPIVersion)
		}
	}
}

func TestEvalFixtureUsesRegisteredTenantBoundIdentity(t *testing.T) {
	eval := readDeployContractFile(t, "deploy/compose/eval.yml")
	fixture := readDeployContractFile(t, "internal/ebpf/testdata/flows.json")
	const sampleAgent = "00000000-0000-0000-0000-000000000101"

	for _, want := range []string{
		"kafka-init:",
		"--topic probectl.ebpf.flows",
		"eval-registry:",
		"eval-registry: { condition: service_completed_successfully }",
		"INSERT INTO agents",
		sampleAgent,
	} {
		if !strings.Contains(eval, want) {
			t.Fatalf("eval stack is missing sample-ingest prerequisite %q", want)
		}
	}
	if !strings.Contains(fixture, `"agent_id":"`+sampleAgent+`"`) {
		t.Fatalf("eBPF fixture does not stamp registered sample agent %s", sampleAgent)
	}
	if strings.Contains(fixture, `"agent_id":"agent-1"`) {
		t.Fatal("eBPF fixture regressed to a non-UUID, unregistered agent identity")
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
		"docs/ebpf-feasibility.md",
		"docs/security/agent-whitepaper.md",
		"docs/deploying-agents.md",
	} {
		body := readDeployContractFile(t, rel)
		for _, banned := range []string{
			"5.4–5.7: CAP_SYS_ADMIN",
			"5.4-5.7: CAP_SYS_ADMIN",
			"5.4–5.7 fallback",
			"5.4-5.7 fallback",
			"CAP_SYS_ADMIN on 5.4–5.7",
			"CAP_SYS_ADMIN on 5.4-5.7",
			"kernels 5.4–5.7: CAP_SYS_ADMIN",
			"kernels 5.4-5.7: CAP_SYS_ADMIN",
			"use SYS_ADMIN on older kernels",
			"SYS_ADMIN only on kernels < 5.8",
			"CAP_SYS_ADMIN only for pre-5.8 kernels",
			"CAP_SYS_ADMIN only as the pre-5.8 fallback",
			"on older kernels, **`CAP_SYS_ADMIN`**",
			"on older kernels, `CAP_SYS_ADMIN`",
			"replace both with CAP_SYS_ADMIN",
			"set `capabilityMode: legacy` for 5.4",
		} {
			if strings.Contains(body, banned) {
				t.Errorf("%s still carries stale broad SYS_ADMIN guidance %q (EBPF-004)", rel, banned)
			}
		}
	}
}

func TestAgentCapabilityPostureAdmissionAuditsLegacyAndExtraCaps(t *testing.T) {
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	schema := readDeployContractFile(t, "deploy/helm/probectl-agent/values.schema.json")
	policy := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/capability-posture-policy.yaml")
	hardening := readDeployContractFile(t, "scripts/check_helm_hardening.sh")
	agentDoc := readDeployContractFile(t, "docs/ebpf-agent.md")
	helmDoc := readDeployContractFile(t, "deploy/helm/README.md")

	for _, want := range []string{
		"capabilityPosture:",
		"enabled: true",
		"policyName: probectl-agent-capability-posture",
		"validationFailureAction: Audit",
		"background: true",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing capability posture default %q (EBPF-007)", want)
		}
	}
	for _, want := range []string{
		"\"capabilityPosture\"",
		"\"validationFailureAction\"",
		"\"Enforce\"",
		"\"Audit\"",
		"\"background\"",
	} {
		if !strings.Contains(schema, want) {
			t.Errorf("agent values.schema.json missing capability posture schema term %q (EBPF-007)", want)
		}
	}
	for _, want := range []string{
		"kind: ClusterPolicy",
		"probectl.dev/finding: EBPF-007",
		"report-legacy-or-extra-ebpf-capabilities",
		"validationFailureAction:",
		"background:",
		"SYS_ADMIN is legacy break-glass",
		"AnyNotIn",
		"ALL",
		"BPF",
		"PERFMON",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("agent capability posture policy missing %q (EBPF-007)", want)
		}
	}
	for _, want := range []string{
		"capability posture ClusterPolicy missing",
		"capability posture policy must scan existing pods",
		"acknowledged legacy mode lost capability posture audit policy",
		"SYS_ADMIN is legacy break-glass",
	} {
		if !strings.Contains(hardening, want) {
			t.Errorf("helm hardening gate missing capability posture assertion %q (EBPF-007)", want)
		}
	}
	for _, doc := range []struct {
		path string
		body string
	}{
		{path: "docs/ebpf-agent.md", body: agentDoc},
		{path: "deploy/helm/README.md", body: helmDoc},
	} {
		for _, want := range []string{
			"probectl-agent-capability-posture",
			"EBPF-007",
			"policy reports",
		} {
			if !strings.Contains(doc.body, want) {
				t.Errorf("%s missing capability posture documentation %q (EBPF-007)", doc.path, want)
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

func TestAgentHelmHealthDefaultsUseExecProbes(t *testing.T) {
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	configmap := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/configmap.yaml")
	daemonset := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/daemonset.yaml")
	schema := readDeployContractFile(t, "deploy/helm/probectl-agent/values.schema.json")
	hardening := readDeployContractFile(t, "scripts/check_helm_hardening.sh")

	for _, want := range []string{
		"mode: exec",
		"stateDir: /var/run/probectl-ebpf-agent",
		"allowPlaintextHTTP: false",
		"explicit plaintext acknowledgement",
	} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing exec health default %q (WIRE-004)", want)
		}
	}
	for _, want := range []string{
		"health_state_dir:",
		"WIRE-004: exec probes; no plaintext listener",
		"health_addr:",
		"compatibility-only HTTP probes",
	} {
		if !strings.Contains(configmap, want) {
			t.Errorf("agent ConfigMap missing health-mode rendering %q (WIRE-004)", want)
		}
	}
	for _, want := range []string{
		"health.mode must be exec or http",
		"health.mode=http opens a plaintext pod listener",
		"health.allowPlaintextHTTP=true",
		"/usr/local/bin/app",
		"healthcheck",
		"--live",
		"--ready",
		"health-state",
		"emptyDir: {}",
	} {
		if !strings.Contains(daemonset, want) {
			t.Errorf("agent DaemonSet missing exec health contract %q (WIRE-004)", want)
		}
	}
	for _, want := range []string{
		"\"health\"",
		"\"mode\"",
		"\"exec\"",
		"\"http\"",
		"\"stateDir\"",
		"\"allowPlaintextHTTP\"",
	} {
		if !strings.Contains(schema, want) {
			t.Errorf("agent values.schema.json missing health schema term %q (WIRE-004)", want)
		}
	}
	for _, want := range []string{
		"default health probe is not exec-based",
		"default chart renders plaintext httpGet health probes",
		"default chart opens plaintext health port 9090",
		"HTTP health mode without health.allowPlaintextHTTP=true",
	} {
		if !strings.Contains(hardening, want) {
			t.Errorf("helm hardening gate missing WIRE-004 assertion %q", want)
		}
	}
}

func TestAgentDocsMentionNonStandardSecretHeaderRedaction(t *testing.T) {
	doc := readDeployContractFile(t, "docs/ebpf-agent.md")
	for _, want := range []string{
		"X-API-Key",
		"X-Amz-Security-Token",
		"custom `*Token*`",
		"X-User-ID",
		"PROBECTL_EBPF_L7_IDENTITY_HEADER_FRAGMENTS",
		"TestRedactPayloadZeroesNonStandardSecretHeaders",
		"TestRedactPayloadZeroesIdentityHeaderValues",
		"TestRedactPayloadHashAllHeaderValues",
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
		"post-GA / out of scope for GA",
	} {
		if !strings.Contains(agentDoc, want) {
			t.Errorf("docs/ebpf-agent.md missing capture limitation contract %q (TRACE-OMIT-F11)", want)
		}
	}
	for _, want := range []string{
		"Go-TLS as an explicitly-scoped",
		"post-GA / out-of-scope-for-GA module",
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
		"TestRedactPayloadZeroesIdentityHeaderValues",
		"TestRedactPayloadHashAllHeaderValues",
		"TestRedactSensitiveHeaderResponseSetCookie",
	} {
		if !strings.Contains(policyTest, want) {
			t.Errorf("l7policy_test.go missing redaction regression %q (TRACE-OMIT-F11)", want)
		}
	}
}

// DPR-124: a consented L7 capture in Kubernetes must come with a read-only view
// of the node's shared-library tree. TLS uprobes attach to an inode and the
// agent image is distroless, so without that mount the advertised
// encrypted-traffic capability can never attach — which is exactly how it
// shipped. The mount is gated on l7Capture.enabled: an agent without capture
// consent gets no view of the node filesystem at all.
func TestAgentHelmL7CaptureMountsTheNodeLibraryTree(t *testing.T) {
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	configmap := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/configmap.yaml")
	daemonset := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/daemonset.yaml")
	schema := readDeployContractFile(t, "deploy/helm/probectl-agent/values.schema.json")

	for _, want := range []string{"hostRoot: /host", "hostLibraryPaths:", "- /usr/lib"} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing node-library default %q (DPR-124)", want)
		}
	}
	if !strings.Contains(configmap, "l7_capture_host_root:") {
		t.Error("agent ConfigMap does not pass l7_capture_host_root to the agent (DPR-124)")
	}
	for _, want := range []string{
		"if and .Values.l7Capture.enabled .Values.l7Capture.hostRoot",
		"node-lib-",
		".Values.l7Capture.hostLibraryPaths",
		"type: Directory",
	} {
		if !strings.Contains(daemonset, want) {
			t.Errorf("agent DaemonSet missing node-library mount contract %q (DPR-124)", want)
		}
	}
	// The mount must be read-only: the agent reads an inode to attach a uprobe,
	// it never writes to the node's libraries.
	libBlock := daemonset
	if i := strings.Index(libBlock, "node-lib-{{ $i }}"); i >= 0 {
		tail := libBlock[i:]
		if j := strings.Index(tail, "{{- end }}"); j > 0 {
			if !strings.Contains(tail[:j], "readOnly: true") {
				t.Error("node-library mount is not readOnly (DPR-124)")
			}
		}
	}
	for _, want := range []string{"\"hostRoot\"", "\"hostLibraryPaths\""} {
		if !strings.Contains(schema, want) {
			t.Errorf("agent values.schema.json missing %q (DPR-124)", want)
		}
	}
}

// The host root is an in-container mount point, so a relative value is an
// operator error that must be refused at config time, not at attach time.
func TestL7CaptureHostRootMustBeAbsolute(t *testing.T) {
	base := func() *Config {
		return &Config{
			TenantID:               "00000000-0000-0000-0000-000000000001",
			FlushInterval:          time.Second,
			L7CaptureEnabled:       true,
			L7CaptureConsentTenant: "00000000-0000-0000-0000-000000000001",
			L7CaptureScope:         []string{"exe:/usr/bin/curl"},
			Bus:                    BusConfig{Mode: "memory"},
		}
	}
	c := base()
	c.L7CaptureHostRoot = "host"
	err := c.validate()
	if err == nil {
		t.Fatal("a relative l7_capture_host_root must be refused")
	}
	if !strings.Contains(err.Error(), "l7_capture_host_root") {
		t.Errorf("refusal must name the key: %v", err)
	}

	c = base()
	c.L7CaptureHostRoot = "/host"
	if err := c.validate(); err != nil {
		t.Errorf("an absolute host root must be accepted: %v", err)
	}
	c = base()
	c.L7CaptureHostRoot = ""
	if err := c.validate(); err != nil {
		t.Errorf("an empty host root (host-installed agent) must be accepted: %v", err)
	}
}

// DPR-128: "the product reports success while delivering nothing" — a consented
// L7 capture that fails to attach left the pod Ready, flows emitting, and only a
// single startup WARN behind. The capture state must be on the metrics endpoint,
// where an operator can alert on requested==1 AND active==0, and the attach
// counter must be there with it.
func TestEBPFAgentExposesL7CaptureStateOnMetrics(t *testing.T) {
	main := readDeployContractFile(t, "cmd/probectl-ebpf-agent/main.go")
	for _, want := range []string{
		"probectl_ebpf_l7_capture_requested",
		"probectl_ebpf_l7_capture_active",
		"probectl_ebpf_l7_attach_failures_total",
		"agent.L7CaptureRequested()",
		"agent.L7CaptureActive()",
		"agent.L7AttachFailures()",
	} {
		if !strings.Contains(main, want) {
			t.Errorf("eBPF agent does not expose %q on /metrics (DPR-128)", want)
		}
	}
	// The DPR-071 delivery gauges must stay wired alongside them.
	for _, want := range []string{"probectl_ebpf_publish_failures_total", "probectl_ebpf_publish_degraded"} {
		if !strings.Contains(main, want) {
			t.Errorf("eBPF agent lost delivery gauge %q (DPR-071)", want)
		}
	}
	docs := readDeployContractFile(t, "docs/ebpf-agent.md")
	for _, want := range []string{"probectl_ebpf_l7_capture_requested", "probectl_ebpf_l7_capture_active"} {
		if !strings.Contains(docs, want) {
			t.Errorf("docs/ebpf-agent.md does not document %q (DPR-128)", want)
		}
	}
}

// A requested capture that is not attached must be distinguishable from one that
// was never requested: both are "no L7 data", and only the first is a fault.
func TestL7CaptureRequestedIsSeparateFromActive(t *testing.T) {
	cfg := &Config{
		TenantID:               "88929fbe-28e5-4f0a-898e-6c4302c55e57",
		FlushInterval:          time.Second,
		L7CaptureEnabled:       true,
		L7CaptureConsentTenant: "88929fbe-28e5-4f0a-898e-6c4302c55e57",
		L7CaptureScope:         []string{"exe:/usr/bin/curl"},
	}
	a := &Agent{cfg: cfg, agg: NewAggregator()}
	if !a.L7CaptureRequested() {
		t.Error("an enabled + consented capture must report requested")
	}
	if a.L7CaptureActive() {
		t.Error("no attached source must report inactive")
	}

	// Consent naming another tenant is not a request for THIS agent.
	other := *cfg
	other.L7CaptureConsentTenant = "00000000-0000-0000-0000-000000000009"
	b := &Agent{cfg: &other, agg: NewAggregator()}
	if b.L7CaptureRequested() {
		t.Error("consent for a different tenant must not count as requested")
	}

	// A recorded fixture replay is not live encrypted-traffic visibility.
	c := &Agent{cfg: cfg, agg: NewAggregator(), l7source: &FixtureL7Source{}}
	if c.L7CaptureActive() {
		t.Error("a fixture replay must not report live capture active")
	}
}

// DPR-125: the TLS uprobe attach registers its probe by WRITING tracefs
// uprobe_events — that is what lets it attach to a distribution-packaged libssl
// with no execute bit, at CAP_PERFMON rather than CAP_SYS_ADMIN. So the mount
// has to be writable on the consented L7 path, and must stay read-only
// everywhere else: writable tracefs is a capability an agent that is not
// capturing has no use for.
func TestAgentHelmTracefsIsWritableOnlyForConsentedL7Capture(t *testing.T) {
	daemonset := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/daemonset.yaml")

	const mount = "readOnly: {{ not .Values.l7Capture.enabled }}"
	if !strings.Contains(daemonset, mount) {
		t.Errorf("the tracefs mount must be read-only unless l7Capture.enabled; want %q in the daemonset", mount)
	}
	// A blanket `readOnly: false` would also make the uprobe path work and is
	// exactly the shortcut to refuse: it would hand write access to every agent
	// in the fleet, including the ones with capture off.
	idx := strings.Index(daemonset, "name: tracefs")
	if idx < 0 {
		t.Fatal("the daemonset no longer mounts tracefs at all")
	}
	window := daemonset[idx:min(idx+400, len(daemonset))]
	if strings.Contains(window, "readOnly: false") {
		t.Error("tracefs is mounted unconditionally writable; it must be gated on l7Capture.enabled")
	}
}

// DPR-127 / D-02, consented 2026-09-18: a scope entry can only name a workload
// the agent can see. In its own PID namespace it sees one process — itself — so
// a consented, scoped capture attached its uprobes and matched nothing.
//
// hostPID and the node's cgroup tree are what make `pid:`, `exe:` and `cgroup:`
// scoping mean anything, and both belong to the consented path alone: an agent
// with capture off has no use for either, and hostPID on every agent in a fleet
// is a much bigger grant than the one that was consented to.
func TestAgentHelmHostVisibilityIsGatedOnConsentedL7Capture(t *testing.T) {
	daemonset := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/daemonset.yaml")

	for _, want := range []string{
		"{{- if .Values.l7Capture.enabled }}",
		"hostPID: true",
		"name: hostcgroup",
		`path: /sys/fs/cgroup`,
		"type: Directory", // never DirectoryOrCreate: a node without cgroup v2 must not schedule
	} {
		if !strings.Contains(daemonset, want) {
			t.Errorf("the consented L7 path needs %q in the daemonset (DPR-127)", want)
		}
	}
	// hostPID must sit inside the l7Capture guard, not beside it.
	guard := strings.Index(daemonset, "{{- if .Values.l7Capture.enabled }}")
	host := strings.Index(daemonset, "hostPID: true")
	if guard < 0 || host < 0 || host < guard {
		t.Error("hostPID must be rendered only when l7Capture.enabled")
	}
	if end := strings.Index(daemonset[guard:], "{{- end }}"); end < 0 || guard+end < host {
		t.Error("hostPID escapes its l7Capture guard — it would be granted to every agent")
	}
	// The blast radius stops at seeing processes. Neither of these is needed for
	// that, and both would widen it.
	for _, forbidden := range []string{"hostNetwork: true", "hostIPC: true"} {
		if strings.Contains(daemonset, forbidden) {
			t.Errorf("%q is not needed to see a process and must not be granted", forbidden)
		}
	}
	// The cgroup tree is read-only: resolving a cgroup id is a stat, never a write.
	idx := strings.Index(daemonset, "name: hostcgroup")
	if idx >= 0 && !strings.Contains(daemonset[idx:min(idx+300, len(daemonset))], "readOnly: true") {
		t.Error("the node cgroup mount must be read-only")
	}
}
