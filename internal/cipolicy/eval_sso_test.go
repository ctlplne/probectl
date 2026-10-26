// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// First-data stores the agent CA encrypted with this key. Switching the same
// evaluation database to SSO must still supply it; a missing key correctly
// stops enrollment-service startup instead of falling back to plaintext.
func TestEvalSSOPreservesEnrollmentEnvelope(t *testing.T) {
	var overlay struct {
		Services map[string]struct {
			Environment map[string]string `yaml:"environment"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "deploy", "compose", "eval-sso.yml")), &overlay); err != nil {
		t.Fatal(err)
	}
	got := overlay.Services["control"].Environment["PROBECTL_ENVELOPE_KEY"]
	if got != "${PROBECTL_EVAL_ENVELOPE_KEY:-}" {
		t.Fatalf("SSO drops the first-data envelope key: PROBECTL_ENVELOPE_KEY = %q", got)
	}
}

// The browser and control plane must reach the same HTTPS issuer, and Dex
// must accept the exact callback advertised by a custom evaluation UI port.
func TestEvalSSOPublishesMatchingIssuerAndCallback(t *testing.T) {
	type service struct {
		Environment map[string]string `yaml:"environment"`
		Ports       []string          `yaml:"ports"`
	}
	var overlay struct {
		Services map[string]service `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "deploy", "compose", "eval-sso.yml")), &overlay); err != nil {
		t.Fatal(err)
	}
	control, dex := overlay.Services["control"], overlay.Services["dex"]
	port := "${PROBECTL_EVAL_DEX_PORT:-5556}"
	if got := control.Environment["PROBECTL_OIDC_ISSUER"]; got != "https://localhost:"+port+"/dex" {
		t.Errorf("issuer is not configurable with the Dex listener: %q", got)
	}
	found := false
	for _, p := range control.Ports {
		if p == "127.0.0.1:"+port+":"+port {
			found = true
		}
	}
	if !found {
		t.Error("browser cannot reach the HTTPS issuer through a loopback-only published port")
	}
	if dex.Environment["DEX_DEMO_PORT"] != port {
		t.Error("Dex listener and issuer port are not synchronized")
	}
	if got := dex.Environment["DEX_DEMO_REDIRECT_URL"]; got == "" || got != control.Environment["PROBECTL_OIDC_REDIRECT_URL"] {
		t.Errorf("Dex callback %q differs from control callback", got)
	}
	template := readRepoFile(t, "deploy", "compose", "dex-demo.yaml")
	for _, want := range []string{`issuer: "https://localhost:{{ .Env.DEX_DEMO_PORT }}/dex"`, `https: "0.0.0.0:{{ .Env.DEX_DEMO_PORT }}"`, `- "{{ .Env.DEX_DEMO_REDIRECT_URL }}"`} {
		if !strings.Contains(template, want) {
			t.Errorf("Dex template omits %q", want)
		}
	}
	// The shared template must retain the production-shaped demo defaults too.
	if err := yaml.Unmarshal([]byte(readRepoFile(t, "deploy", "compose", "dex-demo.yml")), &overlay); err != nil {
		t.Fatal(err)
	}
	dex = overlay.Services["dex"]
	if dex.Environment["DEX_DEMO_PORT"] != "5556" || dex.Environment["DEX_DEMO_REDIRECT_URL"] != "https://localhost:8443/auth/callback" {
		t.Error("shared-template change broke production-demo defaults")
	}
}
