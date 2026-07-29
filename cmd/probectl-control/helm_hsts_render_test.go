// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
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
		"--show-only", "templates/configmap.yaml",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=" + digest,
		"--set", "secrets.envelopeKey=" + envelope,
		"--set-string", "secrets.sessionHMACKey=" + session,
		"--set", "database.url=" + database,
		"--set-string", "control.extraEnv.PROBECTL_AUDIT_WORM_DIR=/var/lib/probectl/audit-worm",
		"--set-string", "control.extraEnv.PROBECTL_WORM_SIGNING_KEY_FILE=/var/lib/probectl/audit-worm/worm-ed25519.pem",
		"--set-string", "control.extraEnv.PROBECTL_SIEM_ENABLED=true",
		"--set-string", "control.extraEnv.PROBECTL_SIEM_ENDPOINT=https://siem.example/ingest",
	}
	cases := []struct {
		name  string
		extra []string
		want  time.Duration
	}{
		{name: "default", want: wantAge},
		{name: "strict", extra: []string{"-f", "deploy/helm/probectl/values-strict.yaml"}, want: wantAge},
		{name: "multi-tenant", extra: []string{"-f", "deploy/helm/probectl/values-multitenant.yaml"}, want: wantAge},
		{name: "multi-region", extra: []string{"-f", "deploy/helm/probectl/values-multiregion.yaml"}, want: wantAge},
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
				"PROBECTL_HSTS_MAX_AGE": string(match[1]),
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
