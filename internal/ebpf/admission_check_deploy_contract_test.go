// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"regexp"
	"strings"
	"testing"
)

// TestAgentAdmissionCheckCronJobIsObserveOnly pins the RTO-12 vanished-webhook
// detection the agent chart ships: a CronJob, on by default with the
// image-integrity policy, that runs `admission-check` from the agent image
// itself (so the policy verifies it), with get-only RBAC on exactly the policy
// and Kyverno's webhook configuration, and a short-lived projected token. It
// detects; it never repairs (docs/guardrails.md G7-8).
func TestAgentAdmissionCheckCronJobIsObserveOnly(t *testing.T) {
	tmpl := readDeployContractFile(t, "deploy/helm/probectl-agent/templates/admission-check-cronjob.yaml")
	values := readDeployContractFile(t, "deploy/helm/probectl-agent/values.yaml")
	doc := readDeployContractFile(t, "docs/deploying-agents.md")

	for _, want := range []string{
		"{{- if and $policy.enabled $check.enabled }}",
		"kind: CronJob",
		"concurrencyPolicy: Forbid",
		`image: "{{ .Values.image.repository }}:{{ $imageTag }}"`,
		"- admission-check",
		"--policy-sha256={{ $sum }}",
		`sha256sum (include "probectl-agent.imageIntegrityRendered" .)`,
		"automountServiceAccountToken: false",
		"expirationSeconds: 600",
		"runAsNonRoot: true",
		"readOnlyRootFilesystem: true",
		`drop: ["ALL"]`,
		`resourceNames: [{{ $policy.policyName | quote }}]`,
		`resourceNames: [{{ $check.kyvernoWebhookConfiguration | quote }}]`,
	} {
		if !strings.Contains(tmpl, want) {
			t.Errorf("admission-check CronJob template missing %q (RTO-12)", want)
		}
	}
	verbs := regexp.MustCompile(`(?m)^\s*verbs:.*$`).FindAllString(tmpl, -1)
	if len(verbs) != 2 {
		t.Fatalf("admission-check ClusterRole has %d verbs lines, want 2", len(verbs))
	}
	for _, v := range verbs {
		if strings.TrimSpace(v) != `verbs: ["get"]` {
			t.Errorf("admission-check ClusterRole grants %q: the check must stay read-only (G7-8)", strings.TrimSpace(v))
		}
	}
	if strings.Contains(tmpl, "automountServiceAccountToken: true") {
		t.Error("admission-check pod automounts a long-lived service-account token")
	}
	for _, want := range []string{"webhookCheck:", "enabled: true", `schedule: "*/5 * * * *"`, "kyvernoWebhookConfiguration: kyverno-resource-validating-webhook-cfg"} {
		if !strings.Contains(values, want) {
			t.Errorf("agent values.yaml missing webhook-check default %q (RTO-12)", want)
		}
	}
	for _, want := range []string{"admission-check", "kube_job_status_failed", "never repairs"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/deploying-agents.md missing webhook-check documentation %q (RTO-12)", want)
		}
	}
}
