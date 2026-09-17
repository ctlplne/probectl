// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"
)

func renderHelmAgentListener(t *testing.T, showOnly string, extra ...string) (string, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--namespace", "probectl",
		"--show-only", showOnly,
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "secrets.envelopeKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--set-string", "secrets.sessionHMACKey=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--set", "database.url=postgres://probectl:render-test@db:5432/probectl?sslmode=require",
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestHelmAgentListenerIsOffByDefaultAndCompleteWhenOn (DPR-046): the chart
// used to have no agent gRPC/mTLS listener at all, so no producer could ever
// attach to a Kubernetes install. Enabled, every piece must be present —
// env, container port, CA export init container, dedicated Service and the
// NetworkPolicy rule — and it must refuse to run without the control TLS
// certificate it serves.
func TestHelmAgentListenerIsOffByDefaultAndCompleteWhenOn(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	for _, tmpl := range []string{"templates/configmap.yaml", "templates/deployment.yaml", "templates/service.yaml", "templates/networkpolicy.yaml"} {
		out, err := renderHelmAgentListener(t, tmpl)
		if err != nil {
			t.Fatalf("%s default render: %v\n%s", tmpl, err, out)
		}
		for _, marker := range []string{"PROBECTL_AGENT_GRPC_ADDR", "agent-grpc", "export-agent-ca", "9443"} {
			if strings.Contains(out, marker) {
				t.Fatalf("%s: agent listener must be off by default, found %q", tmpl, marker)
			}
		}
	}
	on := []string{"--set", "control.agentListener.enabled=true", "--set", "control.agentListener.service.type=NodePort", "--set", "control.agentListener.service.nodePort=30943"}
	cm, err := renderHelmAgentListener(t, "templates/configmap.yaml", on...)
	if err != nil {
		t.Fatalf("configmap: %v\n%s", err, cm)
	}
	for _, want := range []string{
		`PROBECTL_AGENT_GRPC_ADDR: ":9443"`,
		`PROBECTL_AGENT_TLS_CERT_FILE: "/etc/probectl/http-tls/tls.crt"`,
		`PROBECTL_AGENT_TLS_KEY_FILE: "/etc/probectl/http-tls/tls.key"`,
		`PROBECTL_AGENT_TLS_CA_FILE: "/etc/probectl/agent-ca/agent-ca.crt"`,
	} {
		if !strings.Contains(cm, want) {
			t.Fatalf("configmap lacks %q:\n%s", want, cm)
		}
	}
	dep, err := renderHelmAgentListener(t, "templates/deployment.yaml", on...)
	if err != nil {
		t.Fatalf("deployment: %v\n%s", err, dep)
	}
	for _, want := range []string{
		"- name: agent-grpc\n              containerPort: 9443",
		"- name: export-agent-ca",
		`args: ["agent-ca", "export", "/etc/probectl/agent-ca/agent-ca.crt"]`,
		"medium: Memory",
	} {
		if !strings.Contains(dep, want) {
			t.Fatalf("deployment lacks %q:\n%s", want, dep)
		}
	}
	svc, err := renderHelmAgentListener(t, "templates/service.yaml", on...)
	if err != nil {
		t.Fatalf("service: %v\n%s", err, svc)
	}
	for _, want := range []string{"name: probectl-agents", "type: NodePort", "nodePort: 30943", "targetPort: agent-grpc"} {
		if !strings.Contains(svc, want) {
			t.Fatalf("service lacks %q:\n%s", want, svc)
		}
	}
	np, err := renderHelmAgentListener(t, "templates/networkpolicy.yaml", on...)
	if err != nil {
		t.Fatalf("networkpolicy: %v\n%s", err, np)
	}
	if !strings.Contains(np, "port: 9443") {
		t.Fatalf("networkpolicy must admit the listener port:\n%s", np)
	}

	// A bundle the operator exported themselves replaces the init container.
	dep, err = renderHelmAgentListener(t, "templates/deployment.yaml", "--set", "control.agentListener.enabled=true", "--set", "control.agentListener.ca.existingSecret=probectl-agent-ca")
	if err != nil {
		t.Fatalf("deployment with secret: %v\n%s", err, dep)
	}
	if strings.Contains(dep, "export-agent-ca") || !strings.Contains(dep, "secretName: \"probectl-agent-ca\"") {
		t.Fatalf("existingSecret must mount the bundle instead of exporting it:\n%s", dep)
	}

	// No control TLS certificate, no listener: it serves that certificate.
	if out, err := renderHelmAgentListener(t, "templates/configmap.yaml", "--set", "control.agentListener.enabled=true", "--set", "control.tls.enabled=false", "--set", "allowPlaintextHTTP=true"); err == nil {
		t.Fatalf("listener without control TLS must be refused:\n%s", out)
	}
	// extraEnv cannot smuggle the listener settings past the typed value.
	if out, err := renderHelmAgentListener(t, "templates/configmap.yaml", "--set-string", "control.extraEnv.PROBECTL_AGENT_GRPC_ADDR=:9443"); err == nil {
		t.Fatalf("PROBECTL_AGENT_GRPC_ADDR must be reserved for the typed value:\n%s", out)
	}
}
