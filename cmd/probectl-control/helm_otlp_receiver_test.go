// SPDX-License-Identifier: MPL-2.0
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestTheChartCanExposeTheOTLPReceiver (DPR-117): docs/otlp.md documents an
// OTLP/HTTP and OTLP/gRPC ingest surface, and the chart had no way to expose
// it — no container ports, no Service, and a default-deny NetworkPolicy that
// drops collector traffic even if the operator writes the Service by hand. An
// operator following that page on Kubernetes could not receive a single span.
func TestTheChartCanExposeTheOTLPReceiver(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	on := []string{
		"--set", "control.otlp.enabled=true",
		"--set", "networkPolicy.enabled=true",
		"--set", `networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=ingress-nginx`,
		"--set", `control.otlp.ingressFrom[0].podSelector.matchLabels.app=otel-collector`,
	}

	cm, err := renderHelmAgentListener(t, "templates/configmap.yaml", on...)
	if err != nil {
		t.Fatalf("render configmap: %v\n%s", err, cm)
	}
	for _, want := range []string{
		`PROBECTL_OTLP_HTTP_ADDR: ":4318"`,
		`PROBECTL_OTLP_GRPC_ADDR: ":4317"`,
		// §7.12: there is no plaintext ingest — the receiver serves TLS with
		// the control listener's own certificate.
		`PROBECTL_OTLP_TLS_CERT_FILE: "/etc/probectl/http-tls/tls.crt"`,
		`PROBECTL_OTLP_TLS_KEY_FILE: "/etc/probectl/http-tls/tls.key"`,
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("the receiver's configuration must be rendered: missing %q", want)
		}
	}

	svc, err := renderHelmAgentListener(t, "templates/service.yaml", on...)
	if err != nil {
		t.Fatalf("render service: %v\n%s", err, svc)
	}
	for _, want := range []string{"name: probectl-otlp", "name: otlp-http", "targetPort: otlp-http", "name: otlp-grpc"} {
		if !strings.Contains(svc, want) {
			t.Errorf("the receiver needs its own Service, not a widened API Service: missing %q", want)
		}
	}

	np, err := renderHelmAgentListener(t, "templates/networkpolicy.yaml", on...)
	if err != nil {
		t.Fatalf("render networkpolicy: %v\n%s", err, np)
	}
	for _, want := range []string{"port: 4318", "port: 4317", "app: otel-collector"} {
		if !strings.Contains(np, want) {
			t.Errorf("the default-deny policy must admit the named collectors: missing %q", want)
		}
	}

	// Fail closed: TLS is not optional, sources are named, and at least one
	// port must be open.
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"no TLS", "control.tls.enabled", []string{"--set", "control.otlp.enabled=true", "--set", "control.tls.enabled=false"}},
		{"no sources", "control.otlp.ingressFrom", []string{
			"--set", "control.otlp.enabled=true",
			"--set", "networkPolicy.enabled=true",
			"--set", `networkPolicy.ingressFrom[0].namespaceSelector.matchLabels.kubernetes\.io/metadata\.name=ingress-nginx`,
		}},
		{"no ports", "control.otlp.httpPort", []string{
			"--set", "control.otlp.enabled=true",
			"--set", "control.otlp.httpPort=0",
			"--set", "control.otlp.grpcPort=0",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderHelmAgentListener(t, "templates/configmap.yaml", tc.args...)
			if err == nil {
				t.Fatalf("this configuration must be refused, got a render")
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the refusal must name %q, got: %s", tc.want, out)
			}
		})
	}

	// The receiver's Service has a name of its own, so the certificate must
	// carry it. When the API certificate cannot, the receiver takes its own —
	// a lab collector proved the failure first: "certificate is valid for
	// probectl.probectl.svc.cluster.local, not probectl-otlp...".
	own, err := renderHelmAgentListener(t, "templates/configmap.yaml", append(append([]string{}, on...),
		"--set", "control.otlp.tls.existingSecret=probectl-otlp-tls")...)
	if err != nil {
		t.Fatalf("render with a dedicated receiver certificate: %v\n%s", err, own)
	}
	if !strings.Contains(own, `PROBECTL_OTLP_TLS_CERT_FILE: "/etc/probectl/otlp-tls/tls.crt"`) {
		t.Error("a dedicated receiver certificate must be the one the receiver serves")
	}
	ownDep, err := renderHelmAgentListener(t, "templates/deployment.yaml", append(append([]string{}, on...),
		"--set", "control.otlp.tls.existingSecret=probectl-otlp-tls")...)
	if err != nil {
		t.Fatalf("render deployment: %v\n%s", err, ownDep)
	}
	if !strings.Contains(ownDep, `secretName: "probectl-otlp-tls"`) {
		t.Error("the dedicated receiver certificate must be mounted")
	}

	// Off by default: nothing about the receiver appears.
	off, err := renderHelmAgentListener(t, "templates/configmap.yaml")
	if err != nil {
		t.Fatalf("render default: %v\n%s", err, off)
	}
	if strings.Contains(off, "PROBECTL_OTLP_") {
		t.Error("the receiver must be off by default")
	}
}
