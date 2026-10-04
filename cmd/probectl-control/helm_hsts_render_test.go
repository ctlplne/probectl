// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
)

var renderedHSTSMaxAgeRE = regexp.MustCompile(`(?m)^[[:space:]]*PROBECTL_HSTS_MAX_AGE:[[:space:]]*"([^"]+)"[[:space:]]*$`)

// TestHelmRenderedHSTSConfigLoads keeps the chart and the runtime loader on one
// contract: Helm accepts integer seconds, while probectl consumes a Go duration.
// Every shipped profile must therefore render a plain integer followed by "s";
// scientific notation is not a valid time.Duration.
func TestHelmRenderedHSTSConfigLoads(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}

	const (
		digest    = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		envelope  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		session   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		database  = "postgres://probectl:render-test@db:5432/probectl?sslmode=require"
		wantAge   = 31536000 * time.Second
		customAge = 17 * time.Second
	)
	common := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--set", "control.trustedProxies={10.244.0.0/16}",
		"--show-only", "templates/configmap.yaml",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=" + digest,
		"--set", "secrets.existingSecret=probectl-render-runtime",
		"--set", "secrets.envelopeKey=" + envelope,
		"--set-string", "secrets.sessionHMACKey=" + session,
		"--set", "database.url=" + database,
		"--set", "objectStore.enabled=true",
		"--set-string", "objectStore.mountPath=/var/lib/probectl/objects",
		"--set-string", "objectStore.existingClaim=probectl-render-objects-rwx",
		"--set", "audit.worm.enabled=true",
		"--set-string", "audit.worm.existingClaim=probectl-render-audit-worm",
		"--set-string", "control.extraEnv.PROBECTL_SIEM_ENABLED=true",
		"--set-string", "control.extraEnv.PROBECTL_SIEM_ENDPOINT=https://siem.example/ingest",
	}
	cases := []struct {
		name  string
		extra []string
		want  time.Duration
	}{
		{name: "default", want: wantAge},
		// RTO-14: the regulated profile validates a full production surface at
		// startup and the chart refuses to render until the operator supplies the
		// durable bus/TSDB/stores (haDurableSets) plus bus TLS (U-010). Supply them
		// so this renders a complete, installable strict config — the same inputs
		// values-strict.yaml documents.
		{name: "strict", extra: append(
			append([]string{"-f", "deploy/helm/probectl/values-strict.yaml"}, haDurableSets("")...),
			"--set-string", "control.extraEnv.PROBECTL_BUS_TLS_ENABLED=true",
		), want: wantAge},
		// PLAT-02: the multi-replica profiles require shared durable backends, so
		// supply them (haDurableSets, from ha_reference_coherence_test.go).
		{name: "multi-tenant", extra: append([]string{"-f", "deploy/helm/probectl/values-multitenant.yaml"}, haDurableSets("")...), want: wantAge},
		{name: "multi-region", extra: append([]string{"-f", "deploy/helm/probectl/values-multiregion.yaml"}, haDurableSets("")...), want: wantAge},
		{name: "zero", extra: []string{"--set", "ingress.hstsMaxAge=0"}, want: 0},
		{name: "custom", extra: []string{"--set", "ingress.hstsMaxAge=17"}, want: customAge},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{}, common...), tc.extra...)
			cmd := exec.Command("helm", args...)
			cmd.Dir = repoRoot(t)
			rendered, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, rendered)
			}
			match := renderedHSTSMaxAgeRE.FindSubmatch(rendered)
			if len(match) != 2 {
				t.Fatalf("rendered ConfigMap has no single quoted PROBECTL_HSTS_MAX_AGE:\n%s", rendered)
			}
			env := map[string]string{
				"PROBECTL_DATABASE_URL": database,
				// AUTHZ-31: session auth (the default mode) requires a keyed token hash.
				"PROBECTL_SESSION_HMAC_KEY": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				"PROBECTL_HSTS_MAX_AGE":     string(match[1]),
			}
			cfg, err := config.Load(func(key string) string { return env[key] })
			if err != nil {
				t.Fatalf("config.Load rejected rendered HSTS max-age %q: %v", match[1], err)
			}
			if cfg.HSTSMaxAge != tc.want {
				t.Fatalf("rendered HSTS max-age = %s, want %s", cfg.HSTSMaxAge, tc.want)
			}
		})
	}
}
