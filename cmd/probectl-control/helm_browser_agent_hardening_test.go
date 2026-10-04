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

func renderHelmBrowserAgent(t *testing.T, extra ...string) (string, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--namespace", "probectl",
		"--show-only", "templates/browser-agent.yaml",
		"--set", "browserAgent.enabled=true",
		"--set", "browserAgent.image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "browserAgent.configSecret=probectl-browser-agent-config",
		"--set-json", `browserAgent.networkPolicy.egressTo=[{"to":[{"ipBlock":{"cidr":"0.0.0.0/0"}}],"ports":[{"protocol":"TCP","port":443}]}]`,
		"--set", "control.trustedProxies={10.244.0.0/16}",
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

// TestBrowserAgentContainerIsHardened closes the non-architecture half of
// SUP-02: the browser-agent runs a headless Chromium over UNTRUSTED web content
// with Chromium's own sandbox necessarily disabled (the pod forbids the
// privileges it needs — see worker.mjs). The container's securityContext is
// therefore the security boundary, and it must stay maximally locked down. This
// gate-asserts that boundary so it cannot silently regress.
//
// Fail-before (non-vacuity): weaken any one of these (e.g. allow privilege
// escalation, add a capability, drop readOnlyRootFilesystem) and the matching
// assertion fires. The SVID-in-renderer residual (sidecar isolation) is the
// architecture half, deferred in decisions-needed D-36.
func TestBrowserAgentContainerIsHardened(t *testing.T) {
	requireOrSkipHelm(t)
	out, err := renderHelmBrowserAgent(t)
	if err != nil {
		t.Fatalf("render browser-agent.yaml: %v\n%s", err, out)
	}
	for _, want := range []string{
		"runAsNonRoot: true",
		"allowPrivilegeEscalation: false",
		"readOnlyRootFilesystem: true",
		"drop:",
		"ALL",
		"seccompProfile:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("SUP-02: browser-agent container must stay hardened (missing %q) — it is the isolation boundary for untrusted web content:\n%s", want, out)
		}
	}
	// It must NOT run privileged or as root.
	if strings.Contains(out, "privileged: true") {
		t.Error("SUP-02: the browser-agent container must never be privileged")
	}
}
