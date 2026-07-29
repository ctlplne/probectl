// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os/exec"
	"strings"
	"testing"
)

var chartOwnedIngressAnnotations = []string{
	"nginx.ingress.kubernetes.io/ssl-redirect",
	"nginx.ingress.kubernetes.io/force-ssl-redirect",
	"nginx.ingress.kubernetes.io/backend-protocol",
	"nginx.ingress.kubernetes.io/proxy-ssl-verify",
	"nginx.ingress.kubernetes.io/proxy-ssl-secret",
	"nginx.ingress.kubernetes.io/proxy-ssl-server-name",
	"nginx.ingress.kubernetes.io/proxy-ssl-name",
}

func renderHelmIngress(t *testing.T, extra ...string) ([]byte, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--namespace", "probectl",
		"--show-only", "templates/ingress.yaml",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "secrets.envelopeKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--set-string", "secrets.sessionHMACKey=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--set", "database.url=postgres://probectl:render-test@db:5432/probectl?sslmode=require",
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	return cmd.CombinedOutput()
}

func TestHelmIngressRequiresVerifiedBackendTLS(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}

	for _, tc := range []struct {
		name  string
		extra []string
	}{
		{name: "both missing"},
		{name: "trust missing", extra: []string{"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc"}},
		{name: "name missing", extra: []string{"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := renderHelmIngress(t, tc.extra...); err == nil {
				t.Fatalf("chart accepted unverifiable backend TLS:\n%s", out)
			}
		})
	}

	out, err := renderHelmIngress(t,
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
	)
	if err != nil {
		t.Fatalf("verified backend TLS render failed: %v\n%s", err, out)
	}
	for _, want := range []string{
		`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`,
		`nginx.ingress.kubernetes.io/proxy-ssl-verify: "on"`,
		`nginx.ingress.kubernetes.io/proxy-ssl-secret: "probectl/probectl-backend-ca"`,
		`nginx.ingress.kubernetes.io/proxy-ssl-server-name: "on"`,
		`nginx.ingress.kubernetes.io/proxy-ssl-name: "probectl-control.probectl.svc"`,
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("verified ingress missing %q:\n%s", want, out)
		}
	}
}

func TestHelmIngressRejectsOwnedAnnotationOverrides(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	for _, annotation := range chartOwnedIngressAnnotations {
		t.Run(annotation, func(t *testing.T) {
			key := strings.ReplaceAll(annotation, ".", `\.`)
			out, err := renderHelmIngress(t,
				"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
				"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
				"--set-string", "ingress.annotations."+key+"=planted-override",
			)
			if err == nil {
				t.Fatalf("chart accepted reserved ingress annotation %s:\n%s", annotation, out)
			}
			if !strings.Contains(string(out), annotation) {
				t.Fatalf("reserved-annotation failure does not identify %s:\n%s", annotation, out)
			}
		})
	}
}
