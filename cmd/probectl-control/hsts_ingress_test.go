// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"strings"
	"testing"
)

// OPS-009: HSTS must be delivered by a mechanism that ingress-nginx leaves
// ENABLED by default. The chart previously emitted HSTS via a
// configuration-snippet annotation, which ingress-nginx ignores/rejects by
// default since v1.9 (allow-snippet-annotations=false, post CVE-2023-5043/5044)
// — so the header silently vanished. HSTS is now emitted by the application
// (PROBECTL_HSTS_ENABLED, on by default; the header passes through the
// ingress), which is controller-agnostic and always-on.
func TestHSTSNotDeliveredViaSnippetAnnotation(t *testing.T) {
	ingress := readArtifact(t, "deploy/helm/probectl/templates/ingress.yaml")

	// The HSTS header must NOT be set via a configuration-snippet annotation.
	if strings.Contains(ingress, "configuration-snippet") &&
		strings.Contains(ingress, "Strict-Transport-Security") {
		t.Error("ingress emits HSTS via configuration-snippet, which modern ingress-nginx disables by default (OPS-009)")
	}

	// The first-class redirect annotations (which are NOT snippet annotations)
	// must remain so HTTP is forced to HTTPS regardless of snippet policy.
	for _, ann := range []string{
		"nginx.ingress.kubernetes.io/ssl-redirect",
		"nginx.ingress.kubernetes.io/force-ssl-redirect",
	} {
		if !strings.Contains(ingress, ann) {
			t.Errorf("ingress missing first-class redirect annotation %q (OPS-009)", ann)
		}
	}

	// The application path must carry HSTS: the ConfigMap turns it on and sets a
	// max-age, and the middleware emits the header on by default.
	cm := readArtifact(t, "deploy/helm/probectl/templates/configmap.yaml")
	if !strings.Contains(cm, "PROBECTL_HSTS_ENABLED") {
		t.Error("ConfigMap must enable application HSTS (PROBECTL_HSTS_ENABLED) — the supported delivery mechanism (OPS-009)")
	}
	if !strings.Contains(cm, "PROBECTL_HSTS_MAX_AGE") {
		t.Error("ConfigMap must set PROBECTL_HSTS_MAX_AGE so the app HSTS max-age tracks the chart value (OPS-009)")
	}

	mw := readArtifact(t, "internal/control/middleware.go")
	if !strings.Contains(mw, `h.Set("Strict-Transport-Security"`) {
		t.Error("the application middleware must emit Strict-Transport-Security (OPS-009)")
	}
}
