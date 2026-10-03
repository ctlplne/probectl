// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMultitenantHelmValuesShipClickHouseReaderUsers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "probectl", "values-multitenant.yaml"))
	if err != nil {
		t.Fatalf("read values-multitenant.yaml: %v", err)
	}
	var values struct {
		Control struct {
			ExtraEnv map[string]string `yaml:"extraEnv"`
		} `yaml:"control"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse values-multitenant.yaml: %v", err)
	}
	env := values.Control.ExtraEnv
	if env["PROBECTL_DEPLOYMENT_PROFILE"] != "multi-tenant" {
		t.Fatalf("values-multitenant.yaml must set PROBECTL_DEPLOYMENT_PROFILE=multi-tenant, got %q",
			env["PROBECTL_DEPLOYMENT_PROFILE"])
	}
	for _, key := range []string{
		"PROBECTL_PATHSTORE_READER_USER",
		"PROBECTL_FLOWSTORE_READER_USER",
		"PROBECTL_OTELSTORE_READER_USER",
		"PROBECTL_EBPFSTORE_READER_USER",
		"PROBECTL_ENDPOINTSTORE_READER_USER",
	} {
		if env[key] == "" {
			t.Fatalf("values-multitenant.yaml must ship %s so ClickHouse tenant scoping cannot silently downgrade", key)
		}
	}
}

func TestStrictHelmValuesShipRegulatedDeploymentProfile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "probectl", "values-strict.yaml"))
	if err != nil {
		t.Fatalf("read values-strict.yaml: %v", err)
	}
	var values struct {
		Control struct {
			ExtraEnv map[string]string `yaml:"extraEnv"`
		} `yaml:"control"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse values-strict.yaml: %v", err)
	}
	if got := values.Control.ExtraEnv["PROBECTL_DEPLOYMENT_PROFILE"]; got != "regulated" {
		t.Fatalf("values-strict.yaml must set PROBECTL_DEPLOYMENT_PROFILE=regulated, got %q", got)
	}
}

// strictRuntimeEnv reconstructs the environment a strict/regulated control-plane
// pod boots with: the regulated settings values-strict.yaml ships (read from the
// file so a drift there is caught here), the fixed env the ConfigMap always
// renders for this profile, the environment-specific values the chart documents
// as operator-supplied (and refuses to render without — see
// templates/_helpers.tpl probectl.regulatedPreflight), and the secrets.existing
// Secret keys. RTO-14: driving config.Load over this proves a rendered strict
// deployment ACTUALLY starts, rather than reporting "deployed" then crash-looping.
func strictRuntimeEnv(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "probectl", "values-strict.yaml"))
	if err != nil {
		t.Fatalf("read values-strict.yaml: %v", err)
	}
	var values struct {
		Control struct {
			ExtraEnv map[string]string `yaml:"extraEnv"`
		} `yaml:"control"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse values-strict.yaml: %v", err)
	}
	env := map[string]string{}
	// Layer 1: everything values-strict.yaml itself ships (profile, AI-redact,
	// and the five ClickHouse scoped-reader users — RED-001).
	for k, v := range values.Control.ExtraEnv {
		env[k] = v
	}
	if env["PROBECTL_DEPLOYMENT_PROFILE"] != "regulated" {
		t.Fatalf("values-strict.yaml must set PROBECTL_DEPLOYMENT_PROFILE=regulated, got %q", env["PROBECTL_DEPLOYMENT_PROFILE"])
	}
	// Layer 2: fixed env the ConfigMap always renders for this HTTPS profile.
	for k, v := range map[string]string{
		"PROBECTL_REQUIRE_AT_REST_ENCRYPTION": "true",
		"PROBECTL_PUBLIC_TLS":                 "true",
		"PROBECTL_ALLOW_PLAINTEXT_HTTP":       "false",
		"PROBECTL_HTTP_ADDR":                  ":8080",
		"PROBECTL_TLS_CERT_FILE":              "/etc/probectl/http-tls/tls.crt",
		"PROBECTL_TLS_KEY_FILE":               "/etc/probectl/http-tls/tls.key",
		"PROBECTL_AUTH_MODE":                  "session",
		"PROBECTL_AUDIT_WORM_DIR":             "/var/lib/probectl/audit-worm",
		"PROBECTL_OBJECTSTORE_MODE":           "filesystem",
		"PROBECTL_OBJECTSTORE_DIR":            "/var/lib/probectl",
	} {
		env[k] = v
	}
	// Layer 3: the environment-specific values the chart documents as operator-
	// supplied and refuses to render without.
	for k, v := range map[string]string{
		"PROBECTL_SIEM_ENABLED":       "true",
		"PROBECTL_SIEM_ENDPOINT":      "https://siem.example/ingest",
		"PROBECTL_BUS_MODE":           "kafka",
		"PROBECTL_BUS_BROKERS":        "kafka.probectl.svc:9093",
		"PROBECTL_BUS_TLS_ENABLED":    "true",
		"PROBECTL_TSDB_MODE":          "prometheus",
		"PROBECTL_TSDB_URL":           "https://prometheus.probectl.svc:9090",
		"PROBECTL_PATHSTORE_MODE":     "clickhouse",
		"PROBECTL_PATHSTORE_URL":      "https://clickhouse.probectl.svc:8443",
		"PROBECTL_FLOWSTORE_MODE":     "clickhouse",
		"PROBECTL_FLOWSTORE_URL":      "https://clickhouse.probectl.svc:8443",
		"PROBECTL_OTELSTORE_MODE":     "clickhouse",
		"PROBECTL_OTELSTORE_URL":      "https://clickhouse.probectl.svc:8443",
		"PROBECTL_EBPFSTORE_MODE":     "clickhouse",
		"PROBECTL_EBPFSTORE_URL":      "https://clickhouse.probectl.svc:8443",
		"PROBECTL_ENDPOINTSTORE_MODE": "clickhouse",
		"PROBECTL_ENDPOINTSTORE_URL":  "https://clickhouse.probectl.svc:8443",
	} {
		env[k] = v
	}
	// Layer 4: the secrets.existingSecret keys. The DSN MUST use verify-ca/
	// verify-full for this profile (docs/hardening.md; the chart cannot read a
	// Secret's contents, so config.Load enforces the sslmode at startup).
	for k, v := range map[string]string{
		"PROBECTL_DATABASE_URL":     "postgres://probectl:s3cret-not-default@db:5432/probectl?sslmode=verify-full&sslrootcert=/etc/probectl/trust/ca-bundle.crt",
		"PROBECTL_ENVELOPE_KEY":     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"PROBECTL_SESSION_HMAC_KEY": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"PROBECTL_WORM_SIGNING_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	} {
		env[k] = v
	}
	return env
}

// TestStrictProfileRenderedConfigPassesStartupValidation is the RTO-14 GREEN
// proof: the strict profile plus its documented operator-supplied values yields
// a config the control plane ACCEPTS at startup — no "deployed"-then-crashloop.
func TestStrictProfileRenderedConfigPassesStartupValidation(t *testing.T) {
	env := strictRuntimeEnv(t)
	if _, err := Load(func(k string) string { return env[k] }); err != nil {
		t.Fatalf("strict profile + documented values must pass control-plane startup validation, but config.Load failed: %v", err)
	}
}

// TestStrictProfileCrashLoopsWithoutDurableStores is the RTO-14 non-vacuity
// proof: without the durable bus/stores the strict overlay's render-guard now
// requires, the SAME config the pod would boot with is REJECTED at startup —
// which is exactly the crash-loop the guard prevents by failing at render time.
func TestStrictProfileCrashLoopsWithoutDurableStores(t *testing.T) {
	env := strictRuntimeEnv(t)
	// Revert the durable bus/stores back to the lightweight in-memory defaults.
	for _, k := range []string{
		"PROBECTL_BUS_MODE", "PROBECTL_BUS_BROKERS", "PROBECTL_BUS_TLS_ENABLED",
		"PROBECTL_TSDB_MODE", "PROBECTL_TSDB_URL",
		"PROBECTL_PATHSTORE_MODE", "PROBECTL_PATHSTORE_URL",
		"PROBECTL_FLOWSTORE_MODE", "PROBECTL_FLOWSTORE_URL",
		"PROBECTL_OTELSTORE_MODE", "PROBECTL_OTELSTORE_URL",
		"PROBECTL_EBPFSTORE_MODE", "PROBECTL_EBPFSTORE_URL",
		"PROBECTL_ENDPOINTSTORE_MODE", "PROBECTL_ENDPOINTSTORE_URL",
	} {
		delete(env, k)
	}
	if _, err := Load(func(k string) string { return env[k] }); err == nil {
		t.Fatal("expected the regulated profile to be REJECTED at startup on in-memory bus/stores (the crash-loop the render-guard prevents), but config.Load succeeded")
	}
}
