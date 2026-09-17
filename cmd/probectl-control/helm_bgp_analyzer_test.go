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

func renderHelmBGPAnalyzer(t *testing.T, source string, extra ...string) (string, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--namespace", "probectl",
		"--show-only", "templates/bgp-analyzer.yaml",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "secrets.envelopeKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--set-string", "secrets.sessionHMACKey=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--set", "database.url=postgres://probectl:render-test@db:5432/probectl?sslmode=require",
		"--set", "bgpAnalyzer.enabled=true",
		"--set", "bgpAnalyzer.configSecret=bgp-config",
		"--set", "bgpAnalyzer.source=" + source,
		"--set", "bgpAnalyzer.image.digest=sha256:1111111111111111111111111111111111111111111111111111111111111111",
		"--set-string", "bgpAnalyzer.extraEnv.PROBECTL_BUS_BROKERS=kafka.probectl.svc:9093",
		"--set-json", `bgpAnalyzer.networkPolicy.egressTo=[{"to":[{"ipBlock":{"cidr":"10.0.0.0/8"}}],"ports":[{"protocol":"TCP","port":9093}]}]`,
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestHelmBGPAnalyzerFiniteSourcesRunOnce (DPR-059): with an MRT dump the
// analyzer was a Deployment, so a completed run was restarted by Kubernetes
// and the same artifact re-processed and re-published until CrashLoopBackOff.
// Finite sources render as a one-shot Job per release revision; the live
// stream keeps its Deployment.
func TestHelmBGPAnalyzerFiniteSourcesRunOnce(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	for _, source := range []string{"mrt", "replay"} {
		out, err := renderHelmBGPAnalyzer(t, source, "--set", "bgpAnalyzer.sourceFile=/fixtures/routes."+source)
		if err != nil {
			t.Fatalf("%s render: %v\n%s", source, err, out)
		}
		for _, want := range []string{"kind: Job", "restartPolicy: Never", "backoffLimit: 2", "ttlSecondsAfterFinished: 86400", "-bgp-analyzer-r1", "PROBECTL_BGP_ANALYZER_SOURCE_FILE"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: rendered analyzer lacks %q:\n%s", source, want, out)
			}
		}
		if strings.Contains(out, "kind: Deployment") {
			t.Errorf("%s: finite source must not render a Deployment", source)
		}
	}
	out, err := renderHelmBGPAnalyzer(t, "ris-live")
	if err != nil {
		t.Fatalf("ris-live render: %v\n%s", err, out)
	}
	if !strings.Contains(out, "kind: Deployment") || strings.Contains(out, "kind: Job") || strings.Contains(out, "restartPolicy: Never") {
		t.Fatalf("ris-live must render the long-running Deployment:\n%s", out)
	}
}
