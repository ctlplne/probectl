// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

const helmEBPFAgentImage = "0.0.0@sha256:0000000000000000000000000000000000000000000000000000000000000000"

func renderHelmEBPFAgent(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := []string{
		"template", "probectl-agent", "deploy/helm/probectl-agent",
		"--namespace", "probectl",
		"--set", "tenantID=00000000-0000-0000-0000-000000000001",
		"--set", "bus.brokers={kafka.probectl.svc:9093}",
		"--set", "bus.tls.existingSecret=probectl-bus-tls",
		"--set-string", "image.tag=" + helmEBPFAgentImage,
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func containerBlock(rendered, name string) string {
	i := strings.Index(rendered, "- name: "+name+"\n")
	if i < 0 {
		return ""
	}
	rest := rendered[i:]
	if j := strings.Index(rest, "volumeMounts:"); j > 0 {
		rest = rest[:j]
	}
	return rest
}

// TestHelmEBPFAgentCarriesRegisteredIdentityLaneAndBusAuth (DPR-051): the
// chart had no way to give the DaemonSet the collector identity the tenant
// registered, the tenant's bus lane, or bus client credentials, so on a
// production control plane (registry-verified batches, per-tenant lanes,
// authenticated Kafka) it could never deliver a single accepted batch.
func TestHelmEBPFAgentCarriesRegisteredIdentityLaneAndBusAuth(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	if out, err := renderHelmEBPFAgent(t); err == nil {
		t.Fatalf("chart rendered without agentID; the control plane would reject every batch (TENANT-101):\n%s", out)
	} else if !strings.Contains(out, "agentID is required") {
		t.Fatalf("missing agentID must be named in the error, got:\n%s", out)
	}

	out, err := renderHelmEBPFAgent(t,
		"--set", "agentID=e1b3987a-3dbf-4458-8726-9db9224c7af6",
		"--set", "bus.namespace=t-acme",
		"--set", "bus.sasl.mechanism=scram-sha-512",
		"--set", "bus.sasl.existingSecret=probectl-bus-sasl",
		"--set", "bus.tls.clientAuth=true",
	)
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	for _, want := range []string{
		`agent_id: "e1b3987a-3dbf-4458-8726-9db9224c7af6"`, // ConfigMap
		"name: PROBECTL_EBPF_AGENT_ID",                     // env wins over a stale mounted file
		`namespace: "t-acme"`,
		"name: PROBECTL_EBPF_BUS_NAMESPACE",
		"name: PROBECTL_EBPF_BUS_SASL_MECHANISM",
		`value: "scram-sha-512"`,
		"name: PROBECTL_EBPF_BUS_SASL_USER",
		"name: PROBECTL_EBPF_BUS_SASL_PASSWORD",
		`name: "probectl-bus-sasl"`,
		"name: PROBECTL_EBPF_BUS_TLS_CERT_FILE",
		"name: PROBECTL_EBPF_BUS_TLS_KEY_FILE",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
	// Credentials come from the Secret, never from values.
	if strings.Contains(out, "PROBECTL_EBPF_BUS_SASL_PASSWORD\n              value:") {
		t.Error("SASL password rendered inline")
	}
	if out, err := renderHelmEBPFAgent(t, "--set", "agentID=a", "--set", "bus.sasl.mechanism=plain"); err == nil {
		t.Fatalf("SASL without a Secret must refuse to render:\n%s", out)
	}
	if out, err := renderHelmEBPFAgent(t, "--set", "agentID=a", "--set", "bus.tls.existingSecret=", "--set", "bus.tls.clientAuth=true"); err == nil {
		t.Fatalf("clientAuth without a Secret to read the pair from must refuse to render:\n%s", out)
	}
}

// TestHelmEBPFAgentSeccompInstallerRunsOutsideTheProfileItInstalls (DPR-052):
// the strict Localhost seccomp profile was declared at pod level, so it also
// governed the initContainer whose job is to write that profile onto the
// node. On any node without the profile the pod stayed in
// Init:CreateContainerError forever.
func TestHelmEBPFAgentSeccompInstallerRunsOutsideTheProfileItInstalls(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := renderHelmEBPFAgent(t, "--set", "agentID=a")
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	dsAt, initAt := strings.Index(out, "kind: DaemonSet"), 0
	if dsAt < 0 {
		t.Fatalf("no DaemonSet rendered:\n%s", out)
	}
	ds := out[dsAt:]
	if initAt = strings.Index(ds, "initContainers:"); initAt < 0 {
		t.Fatalf("no initContainers rendered:\n%s", ds)
	}
	podSpec := ds[:initAt]
	if strings.Contains(podSpec, "seccompProfile") {
		t.Fatal("pod-level seccompProfile would govern the installer initContainer too")
	}
	installer := containerBlock(ds, "install-seccomp-profile")
	if !strings.Contains(installer, "type: RuntimeDefault") || strings.Contains(installer, "type: Localhost") {
		t.Fatalf("installer initContainer must run under RuntimeDefault, not the profile it installs:\n%s", installer)
	}
	agent := containerBlock(ds, "agent")
	if !strings.Contains(agent, "type: Localhost") || !strings.Contains(agent, "localhostProfile: probectl/seccomp.json") {
		t.Fatalf("agent container must keep the strict Localhost profile (EBPF-003):\n%s", agent)
	}
}

// TestHelmEBPFAgentMountsTraceFS (DPR-054): the live loader reads the
// tracepoint's event id from tracefs, which a container does not see unless
// the node's /sys/kernel/tracing is mounted in; without it the agent died at
// attach with "neither debugfs nor tracefs are mounted".
func TestHelmEBPFAgentMountsTraceFS(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := renderHelmEBPFAgent(t, "--set", "agentID=a")
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	for _, want := range []string{
		"mountPath: /sys/kernel/tracing\n              readOnly: true",
		"path: /sys/kernel/tracing\n            type: Directory",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered chart lacks %q", want)
		}
	}
}

// DPR-071: the chart pins the per-record bound so a busy host's cumulative
// service map is split across records instead of outgrowing Kafka's message
// limit; the schema refuses to switch the bound off.
func TestHelmEBPFAgentBoundsPublishedRecords(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := renderHelmEBPFAgent(t, "--set", "agentID=a")
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	if !strings.Contains(out, "max_batch_bytes: 786432") {
		t.Errorf("default render must bound records at 786432 bytes:\n%s", out)
	}
	out, err = renderHelmEBPFAgent(t, "--set", "agentID=a", "--set", "maxBatchBytes=524288")
	if err != nil {
		t.Fatalf("render: %v\n%s", err, out)
	}
	if !strings.Contains(out, "max_batch_bytes: 524288") {
		t.Errorf("maxBatchBytes must reach the agent config:\n%s", out)
	}
	if out, err := renderHelmEBPFAgent(t, "--set", "agentID=a", "--set", "maxBatchBytes=0"); err == nil {
		t.Errorf("maxBatchBytes=0 (unbounded) must be refused by the schema:\n%s", out)
	}
}
