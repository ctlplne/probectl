// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"strings"
	"testing"
)

// TestArgoCDHealthChecksGateTheAgentPolicyWave pins RTO-12's GitOps ordering:
// with readinessGate=external, the DaemonSet's Argo CD wave waits behind the
// image-integrity policy only if Argo CD can assess the policy. The shipped
// Lua is Healthy only when Kyverno reports the policy ready AND registered in
// its webhook. (scripts/check_gitops_manifests.sh SELFTEST plants weakened
// copies; the Lua was exercised with `argocd admin settings resource-overrides
// health`, and the kind smoke asserts the live status carries both fields.)
func TestArgoCDHealthChecksGateTheAgentPolicyWave(t *testing.T) {
	cm := readDeployContractFile(t, "deploy/gitops/argocd/argocd-cm-kyverno-health.yaml")
	for _, want := range []string{
		"kind: ConfigMap",
		"name: argocd-cm",
		"namespace: argocd",
		"resource.customizations.health.policies.kyverno.io_ImageValidatingPolicy: |",
		"resource.customizations.health.policies.kyverno.io_ValidatingPolicy: |",
		"--type merge",
	} {
		if !strings.Contains(cm, want) {
			t.Errorf("argocd-cm-kyverno-health.yaml missing %q (RTO-12)", want)
		}
	}
	for _, rule := range []string{
		`hs.status = "Progressing"`,
		`if c.type == "WebhookConfigured" and c.status == "True" then`,
		`if cs.ready == true and webhookConfigured then`,
		`hs.status = "Healthy"`,
	} {
		if got := strings.Count(cm, rule); got != 2 {
			t.Errorf("each of the two health checks must carry %q once (found %d)", rule, got)
		}
	}
	for _, doc := range []string{"docs/deploying-agents.md", "deploy/gitops/README.md"} {
		if !strings.Contains(readDeployContractFile(t, doc), "argocd-cm-kyverno-health.yaml") {
			t.Errorf("%s does not point at the Argo CD Kyverno health checks (RTO-12)", doc)
		}
	}
	tmpl := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/image-integrity-policy.yaml")
	if !strings.Contains(tmpl, `argocd.argoproj.io/sync-wave: "-1"`) || !strings.Contains(tmpl, "argocd-cm-kyverno-health.yaml") {
		t.Error("the image-integrity policy must sit in sync-wave -1 and name the health check for readinessGate=external (RTO-12)")
	}
}
