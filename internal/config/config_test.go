// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

const testSessionHMACKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
const testDatabaseURL = "postgres://probectl:test-only@localhost:5432/probectl?sslmode=require"

func envFunc(m map[string]string) func(string) string {
	return func(k string) string {
		if value, ok := m[k]; ok {
			return value
		}
		// Database configuration is required in real loads. Most tests in this
		// package exercise an unrelated default, so make their test-only DSN
		// explicit while the dedicated empty-environment test below bypasses
		// this helper and proves production loading fails closed.
		if k == "PROBECTL_DATABASE_URL" {
			return testDatabaseURL
		}
		return ""
	}
}

func durableTenantProfileEnv(profile string) map[string]string {
	return map[string]string{
		"PROBECTL_DEPLOYMENT_PROFILE":        profile,
		"PROBECTL_SESSION_HMAC_KEY":          testSessionHMACKeyHex,
		"PROBECTL_BUS_MODE":                  "kafka",
		"PROBECTL_BUS_BROKERS":               "kafka.example:9093",
		"PROBECTL_BUS_TLS_ENABLED":           "true",
		"PROBECTL_TSDB_MODE":                 "prometheus",
		"PROBECTL_TSDB_URL":                  "https://prometheus.example",
		"PROBECTL_PATHSTORE_MODE":            "clickhouse",
		"PROBECTL_PATHSTORE_URL":             "https://clickhouse.example:8443",
		"PROBECTL_PATHSTORE_READER_USER":     "probectl_path_reader",
		"PROBECTL_FLOWSTORE_MODE":            "clickhouse",
		"PROBECTL_FLOWSTORE_URL":             "https://clickhouse.example:8443",
		"PROBECTL_FLOWSTORE_READER_USER":     "probectl_flow_reader",
		"PROBECTL_OTELSTORE_MODE":            "clickhouse",
		"PROBECTL_OTELSTORE_URL":             "https://clickhouse.example:8443",
		"PROBECTL_OTELSTORE_READER_USER":     "probectl_otel_reader",
		"PROBECTL_EBPFSTORE_MODE":            "clickhouse",
		"PROBECTL_EBPFSTORE_URL":             "https://clickhouse.example:8443",
		"PROBECTL_EBPFSTORE_READER_USER":     "probectl_ebpf_reader",
		"PROBECTL_ENDPOINTSTORE_MODE":        "clickhouse",
		"PROBECTL_ENDPOINTSTORE_URL":         "https://clickhouse.example:8443",
		"PROBECTL_ENDPOINTSTORE_READER_USER": "probectl_endpoint_reader",
		"PROBECTL_AUDIT_WORM_DIR":            "/var/lib/probectl/audit-worm",
		"PROBECTL_WORM_SIGNING_KEY_FILE":     "/var/lib/probectl/keys/audit-worm-ed25519.pem",
		"PROBECTL_SIEM_ENABLED":              "true",
		"PROBECTL_SIEM_ENDPOINT":             "https://siem.example/ingest",
	}
}

func singleOIDCSessionEnv() map[string]string {
	return map[string]string{
		"PROBECTL_DEPLOYMENT_PROFILE": "single",
		"PROBECTL_AUTH_MODE":          "session",
		"PROBECTL_OIDC_ISSUER":        "https://idp.example.test",
		"PROBECTL_OIDC_CLIENT_ID":     "probectl",
		"PROBECTL_OIDC_CLIENT_SECRET": "client-secret",
		"PROBECTL_OIDC_REDIRECT_URL":  "https://probectl.example.test/auth/callback",
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want :8080", cfg.HTTPAddr)
	}
	if cfg.LogLevel != "info" || cfg.LogFormat != "json" {
		t.Errorf("log defaults = %q/%q, want info/json", cfg.LogLevel, cfg.LogFormat)
	}
	if cfg.MigrateOnBoot {
		t.Error("MigrateOnBoot should default to false")
	}
	if !cfg.HSTSEnabled {
		t.Error("HSTSEnabled should default to true")
	}
	if cfg.DatabaseMaxConns != 25 { // SCALE-009: raised default
		t.Errorf("DatabaseMaxConns = %d, want 25", cfg.DatabaseMaxConns)
	}
	if cfg.DatabaseMinConns != 2 { // SCALE-009: warm floor
		t.Errorf("DatabaseMinConns = %d, want 2", cfg.DatabaseMinConns)
	}
	if cfg.FairnessQueryConcurrency != 4 {
		t.Errorf("FairnessQueryConcurrency = %d, want 4", cfg.FairnessQueryConcurrency)
	}
	if cfg.FairnessQueriesPerMin != 120 {
		t.Errorf("FairnessQueriesPerMin = %v, want 120", cfg.FairnessQueriesPerMin)
	}
	if cfg.SessionIdleTimeout != 30*time.Minute {
		t.Errorf("SessionIdleTimeout = %v, want 30m", cfg.SessionIdleTimeout)
	}
}

func TestLoadRejectsMissingDatabaseURLByDefault(t *testing.T) {
	_, err := Load(func(string) string { return "" })
	if err == nil {
		t.Fatal("empty-environment config load succeeded with no PostgreSQL credential")
	}
	if !strings.Contains(err.Error(), "PROBECTL_DATABASE_URL is required") {
		t.Fatalf("empty-environment error = %q, want required PROBECTL_DATABASE_URL guidance", err)
	}
}

func TestExplicitDevDatabaseURLRemainsSupported(t *testing.T) {
	const explicit = "postgres://probectl:probectl@postgres:5432/probectl?sslmode=disable"
	cfg, err := Load(envFunc(map[string]string{"PROBECTL_DATABASE_URL": explicit}))
	if err != nil {
		t.Fatalf("explicit development DSN should remain supported: %v", err)
	}
	if cfg.DatabaseURL != explicit {
		t.Fatalf("explicit development DSN = %q, want unchanged %q", cfg.DatabaseURL, explicit)
	}
}

func TestKeywordDatabaseDSNRejected(t *testing.T) {
	const (
		writerSecret = "writer_keyword_secret_7654"
		readerSecret = "reader keyword secret 7654"
	)
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "writer",
			env: map[string]string{
				"PROBECTL_DATABASE_URL": "host=db user=writer password=" + writerSecret + " dbname=probectl sslmode=disable",
			},
		},
		{
			name: "reader",
			env: map[string]string{
				"PROBECTL_DATABASE_URL":      testDatabaseURL,
				"PROBECTL_DATABASE_READ_URL": "host=read-db user=reader password='" + readerSecret + "' dbname=probectl sslmode=disable",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(envFunc(tt.env))
			if err == nil {
				t.Fatal("PostgreSQL keyword/value DSN was accepted; want a postgres:// or postgresql:// URL")
			}
			for _, secret := range []string{writerSecret, readerSecret} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("database validation error disclosed credential %q: %v", secret, err)
				}
			}
		})
	}
}

func TestKeywordDatabaseDSNRedactionFailsClosed(t *testing.T) {
	const (
		writerSecret    = "writer_keyword_secret_8765"
		writerSSLSecret = "writer ssl keyword secret 8765"
		readerSecret    = "reader_keyword_secret_8765"
	)
	cfg := &Config{
		DatabaseURL: "host=db user=writer password=" + writerSecret +
			" sslpassword='" + writerSSLSecret + "' dbname=probectl",
		DatabaseReadURL: "host=read-db user=reader password=" + readerSecret +
			" dbname=probectl",
	}

	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("cfg", "config", cfg)
	snapshot, err := json.Marshal(cfg.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	out := log.String() + string(snapshot)
	for _, secret := range []string{writerSecret, writerSSLSecret, readerSecret} {
		if strings.Contains(out, secret) {
			t.Fatalf("keyword/value database credential leaked through config redaction: %s", out)
		}
	}
}

func TestSessionIdleTimeoutOverride(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{"PROBECTL_SESSION_IDLE_TIMEOUT": "45m"}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.SessionIdleTimeout != 45*time.Minute {
		t.Fatalf("SessionIdleTimeout = %v, want 45m", cfg.SessionIdleTimeout)
	}
}

// TENANT-004: DB-enforced ClickHouse tenant isolation must default ON across
// ALL five telemetry planes in the multi-tenant/regulated profile (defense in
// depth above app-layer WHERE scoping, guardrail 7.1) and stay OFF in the
// single-tenant profile.
func TestDeploymentProfileDefaultsCHScoping(t *testing.T) {
	t.Run("single keeps app-layer scoping", func(t *testing.T) {
		cfg, err := Load(envFunc(nil)) // default profile = single
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.DeploymentProfile != "single" {
			t.Fatalf("DeploymentProfile = %q, want single", cfg.DeploymentProfile)
		}
		for name, on := range map[string]bool{
			"flow": cfg.FlowCHTenantScoping, "otel": cfg.OTelCHTenantScoping,
			"ebpf": cfg.EBPFCHTenantScoping, "path": cfg.PathCHTenantScoping,
			"endpoint": cfg.EndpointCHTenantScoping,
		} {
			if on {
				t.Errorf("single profile: %s CH scoping defaulted ON, want OFF", name)
			}
		}
	})
	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile+" enables DB-layer isolation on every plane", func(t *testing.T) {
			cfg, err := Load(envFunc(durableTenantProfileEnv(profile)))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			for name, on := range map[string]bool{
				"flow": cfg.FlowCHTenantScoping, "otel": cfg.OTelCHTenantScoping,
				"ebpf": cfg.EBPFCHTenantScoping, "path": cfg.PathCHTenantScoping,
				"endpoint": cfg.EndpointCHTenantScoping,
			} {
				if !on {
					t.Errorf("%s profile: %s CH scoping defaulted OFF, want ON (DB-layer isolation)", profile, name)
				}
			}
		})
	}
	t.Run("single profile may explicitly enable one DB scoping plane", func(t *testing.T) {
		env := map[string]string{
			"PROBECTL_OTELSTORE_TENANT_SCOPING": "true",
			"PROBECTL_OTELSTORE_READER_USER":    "probectl_otel_reader",
		}
		cfg, err := Load(envFunc(env))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if !cfg.OTelCHTenantScoping {
			t.Error("explicit PROBECTL_OTELSTORE_TENANT_SCOPING=true did not apply in single profile")
		}
		if cfg.FlowCHTenantScoping {
			t.Error("flow scoping should still be OFF from the single profile")
		}
	})
}

func TestTenantProfilesRequireClickHouseReaderUsers(t *testing.T) {
	for _, profile := range []string{"multi-tenant", "regulated"} {
		for _, tc := range []struct {
			name string
			env  string
		}{
			{name: "path", env: "PROBECTL_PATHSTORE_READER_USER"},
			{name: "flow", env: "PROBECTL_FLOWSTORE_READER_USER"},
			{name: "otel", env: "PROBECTL_OTELSTORE_READER_USER"},
			{name: "ebpf", env: "PROBECTL_EBPFSTORE_READER_USER"},
			{name: "endpoint", env: "PROBECTL_ENDPOINTSTORE_READER_USER"},
		} {
			t.Run(profile+" missing "+tc.name+" reader", func(t *testing.T) {
				env := durableTenantProfileEnv(profile)
				delete(env, tc.env)
				_, err := Load(envFunc(env))
				if err == nil {
					t.Fatal("tenant profile without a ClickHouse scoped reader user should fail closed")
				}
				msg := err.Error()
				if !strings.Contains(msg, tc.env) || !strings.Contains(msg, "PROBECTL_DEPLOYMENT_PROFILE="+profile) {
					t.Fatalf("error %q missing reader env/profile context", msg)
				}
			})
		}
	}
}

func TestTenantProfilesRejectClickHouseScopingDowngrade(t *testing.T) {
	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile, func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_OTELSTORE_TENANT_SCOPING"] = "false"
			_, err := Load(envFunc(env))
			if err == nil {
				t.Fatal("tenant profile with ClickHouse scoping disabled should fail closed")
			}
			msg := err.Error()
			if !strings.Contains(msg, "PROBECTL_OTELSTORE_TENANT_SCOPING=true") || !strings.Contains(msg, "PROBECTL_OTELSTORE_MODE=clickhouse") {
				t.Fatalf("error %q missing scoping downgrade context", msg)
			}
		})
	}
}

func TestTenantProfilesRejectVolatileStores(t *testing.T) {
	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile, func(t *testing.T) {
			_, err := Load(envFunc(map[string]string{
				"PROBECTL_DEPLOYMENT_PROFILE": profile,
				"PROBECTL_SESSION_HMAC_KEY":   testSessionHMACKeyHex,
			}))
			if err == nil {
				t.Fatal("tenant profile with default memory modes should fail closed")
			}
			msg := err.Error()
			for _, want := range []string{
				"PROBECTL_BUS_MODE=memory",
				"PROBECTL_TSDB_MODE=memory",
				"PROBECTL_PATHSTORE_MODE=memory",
				"PROBECTL_FLOWSTORE_MODE=memory",
				"PROBECTL_OTELSTORE_MODE=memory",
				"PROBECTL_EBPFSTORE_MODE=memory",
				"PROBECTL_ENDPOINTSTORE_MODE=memory",
			} {
				if !strings.Contains(msg, want) {
					t.Fatalf("error %q missing volatile mode %s", msg, want)
				}
			}
		})
	}
}

func TestDatastoreTLSRequiredForTenantProfiles(t *testing.T) {
	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile+" accepts TLS datastores", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_DATABASE_READ_URL"] = "postgres://probectl_reader:secret@pg-ro.example:5432/probectl?sslmode=verify-full"
			env["PROBECTL_DATAPLANES"] = "us=https://clickhouse-us.example:8443;eu=https://clickhouse-eu.example:8443"
			if _, err := Load(envFunc(env)); err != nil {
				t.Fatalf("secure datastore URLs should load: %v", err)
			}
		})

		t.Run(profile+" rejects plaintext postgres writer", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_DATABASE_URL"] = "postgres://probectl:secret@pg.example:5432/probectl?sslmode=disable"
			_, err := Load(envFunc(env))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_DATABASE_URL") || !strings.Contains(err.Error(), "sslmode=require") {
				t.Fatalf("plaintext writer DSN should fail closed with sslmode guidance, got %v", err)
			}
		})

		t.Run(profile+" rejects plaintext postgres read replica", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_DATABASE_READ_URL"] = "postgres://probectl_reader:secret@pg-ro.example:5432/probectl"
			_, err := Load(envFunc(env))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_DATABASE_READ_URL") || !strings.Contains(err.Error(), "sslmode=require") {
				t.Fatalf("plaintext read-replica DSN should fail closed with sslmode guidance, got %v", err)
			}
		})

		for _, tc := range []struct {
			name   string
			urlEnv string
		}{
			{name: "path", urlEnv: "PROBECTL_PATHSTORE_URL"},
			{name: "flow", urlEnv: "PROBECTL_FLOWSTORE_URL"},
			{name: "otel", urlEnv: "PROBECTL_OTELSTORE_URL"},
			{name: "ebpf", urlEnv: "PROBECTL_EBPFSTORE_URL"},
			{name: "endpoint", urlEnv: "PROBECTL_ENDPOINTSTORE_URL"},
		} {
			t.Run(profile+" rejects plaintext "+tc.name+" clickhouse", func(t *testing.T) {
				env := durableTenantProfileEnv(profile)
				env[tc.urlEnv] = "http://clickhouse.example:8123"
				_, err := Load(envFunc(env))
				if err == nil || !strings.Contains(err.Error(), tc.urlEnv) || !strings.Contains(err.Error(), "https://") {
					t.Fatalf("plaintext %s should fail closed with https guidance, got %v", tc.urlEnv, err)
				}
			})
		}

		t.Run(profile+" rejects plaintext residency dataplane", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_DATAPLANES"] = "us=http://clickhouse-us.example:8123"
			_, err := Load(envFunc(env))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_DATAPLANES") || !strings.Contains(err.Error(), "https://") {
				t.Fatalf("plaintext dataplane should fail closed with https guidance, got %v", err)
			}
		})
	}
}

func TestDatastoreTLSAllowsSingleProfileDevLoopback(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"PROBECTL_DEPLOYMENT_PROFILE": "single",
		"PROBECTL_DATABASE_URL":       "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable",
		"PROBECTL_PATHSTORE_MODE":     "clickhouse",
		"PROBECTL_PATHSTORE_URL":      "http://localhost:8123",
	}))
	if err != nil {
		t.Fatalf("single-profile dev loopback datastore URLs should remain loadable: %v", err)
	}
	if cfg.DatabaseURL == "" || cfg.PathStoreURL == "" {
		t.Fatalf("expected dev datastore URLs to load, got database=%q path=%q", cfg.DatabaseURL, cfg.PathStoreURL)
	}
}

func TestSessionHMACKeyRequiredForTenantProfiles(t *testing.T) {
	t.Run("single oidc session requires session hmac key", func(t *testing.T) {
		_, err := Load(envFunc(singleOIDCSessionEnv()))
		if err == nil || !strings.Contains(err.Error(), "PROBECTL_SESSION_HMAC_KEY is required") {
			t.Fatalf("single-profile OIDC session auth without session HMAC key should fail closed; got %v", err)
		}
	})

	t.Run("single local session without oidc may omit session hmac key", func(t *testing.T) {
		cfg, err := Load(envFunc(map[string]string{
			"PROBECTL_DEPLOYMENT_PROFILE": "single",
			"PROBECTL_AUTH_MODE":          "session",
		}))
		if err != nil {
			t.Fatalf("single-profile local session config without OIDC should remain loadable: %v", err)
		}
		if len(cfg.SessionHMACKey) != 0 {
			t.Fatalf("SessionHMACKey length = %d, want omitted local/dev key", len(cfg.SessionHMACKey))
		}
	})

	t.Run("single oidc session accepts valid session hmac key", func(t *testing.T) {
		env := singleOIDCSessionEnv()
		env["PROBECTL_SESSION_HMAC_KEY"] = testSessionHMACKeyHex
		cfg, err := Load(envFunc(env))
		if err != nil {
			t.Fatalf("single-profile OIDC session auth with HMAC key should load: %v", err)
		}
		if len(cfg.SessionHMACKey) != crypto.KeySize {
			t.Fatalf("SessionHMACKey length = %d, want %d", len(cfg.SessionHMACKey), crypto.KeySize)
		}
	})

	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile+" requires session hmac key", func(t *testing.T) {
			_, err := Load(envFunc(map[string]string{
				"PROBECTL_DEPLOYMENT_PROFILE": profile,
				"PROBECTL_AUTH_MODE":          "session",
			}))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_SESSION_HMAC_KEY is required") {
				t.Fatalf("missing session HMAC key should fail closed; got %v", err)
			}
		})

		t.Run(profile+" accepts valid session hmac key", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_AUTH_MODE"] = "session"
			cfg, err := Load(envFunc(env))
			if err != nil {
				t.Fatalf("load with session HMAC key: %v", err)
			}
			if len(cfg.SessionHMACKey) != crypto.KeySize {
				t.Fatalf("SessionHMACKey length = %d, want %d", len(cfg.SessionHMACKey), crypto.KeySize)
			}
		})
	}
}

func TestSessionHMACKeyHexValidation(t *testing.T) {
	for name, value := range map[string]string{
		"bad hex":   "not-hex",
		"too short": "000102",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Load(envFunc(map[string]string{"PROBECTL_SESSION_HMAC_KEY": value}))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_SESSION_HMAC_KEY") {
				t.Fatalf("invalid session HMAC key should be rejected, got %v", err)
			}
		})
	}
}

func TestResultPipelineConfig(t *testing.T) {
	// Defaults: in-process bus + TSDB, no external dependencies.
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BusMode != "memory" || cfg.TSDBMode != "memory" {
		t.Errorf("pipeline defaults = %q/%q, want memory/memory", cfg.BusMode, cfg.TSDBMode)
	}
	if cfg.IngestWriteWorkers != 4 || cfg.IngestWriteQueue != 0 {
		t.Errorf("ingest write defaults = workers %d queue %d, want workers 4 queue 0", cfg.IngestWriteWorkers, cfg.IngestWriteQueue)
	}

	// Kafka + Prometheus with their required settings (brokers are trimmed).
	// Kafka requires TLS (U-010) — the happy path enables it.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_BUS_MODE":             "kafka",
		"PROBECTL_BUS_BROKERS":          "b1:9092, b2:9092",
		"PROBECTL_BUS_TLS_ENABLED":      "true",
		"PROBECTL_TSDB_MODE":            "prometheus",
		"PROBECTL_TSDB_URL":             "http://prom:9090",
		"PROBECTL_INGEST_WRITE_WORKERS": "12",
		"PROBECTL_INGEST_WRITE_QUEUE":   "2048",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.BusBrokers) != 2 || cfg.BusBrokers[0] != "b1:9092" || cfg.BusBrokers[1] != "b2:9092" {
		t.Errorf("BusBrokers = %v, want [b1:9092 b2:9092]", cfg.BusBrokers)
	}
	if cfg.IngestWriteWorkers != 12 || cfg.IngestWriteQueue != 2048 {
		t.Errorf("ingest write config = workers %d queue %d, want workers 12 queue 2048", cfg.IngestWriteWorkers, cfg.IngestWriteQueue)
	}

	// kafka without brokers and prometheus without a URL must both fail.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_BUS_MODE": "kafka"})); err == nil || !strings.Contains(err.Error(), "PROBECTL_BUS_BROKERS") {
		t.Errorf("kafka without brokers should fail with a brokers error, got %v", err)
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_TSDB_MODE": "prometheus"})); err == nil || !strings.Contains(err.Error(), "PROBECTL_TSDB_URL") {
		t.Errorf("prometheus without a URL should fail with a URL error, got %v", err)
	}

	// U-010 fail-closed: kafka without TLS is refused unless the explicit
	// dev-only plaintext flag is set.
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_BUS_MODE":    "kafka",
		"PROBECTL_BUS_BROKERS": "b1:9092",
	})); err == nil || !strings.Contains(err.Error(), "kafka without TLS") {
		t.Errorf("plaintext kafka should be refused, got %v", err)
	}
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_BUS_MODE":            "kafka",
		"PROBECTL_BUS_BROKERS":         "b1:9092",
		"PROBECTL_BUS_ALLOW_PLAINTEXT": "true",
	})); err != nil {
		t.Errorf("explicit dev plaintext flag should load, got %v", err)
	}
}

func TestFlowEnrichmentCacheMaxConfig(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FlowEnrichCacheMax != 65536 {
		t.Fatalf("FlowEnrichCacheMax default = %d, want 65536", cfg.FlowEnrichCacheMax)
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_FLOW_ENRICH_CACHE_MAX": "128"}))
	if err != nil {
		t.Fatalf("load override: %v", err)
	}
	if cfg.FlowEnrichCacheMax != 128 {
		t.Fatalf("FlowEnrichCacheMax override = %d, want 128", cfg.FlowEnrichCacheMax)
	}
	if _, err := Load(envFunc(map[string]string{"PROBECTL_FLOW_ENRICH_CACHE_MAX": "0"})); err == nil || !strings.Contains(err.Error(), "PROBECTL_FLOW_ENRICH_CACHE_MAX") {
		t.Fatalf("zero cache max should fail closed, got %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"PROBECTL_HTTP_ADDR":          ":9000",
		"PROBECTL_LOG_LEVEL":          "debug",
		"PROBECTL_LOG_FORMAT":         "text",
		"PROBECTL_MIGRATE_ON_BOOT":    "true",
		"PROBECTL_SHUTDOWN_TIMEOUT":   "30s",
		"PROBECTL_DATABASE_MAX_CONNS": "20",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPAddr != ":9000" || cfg.LogLevel != "debug" || cfg.LogFormat != "text" {
		t.Errorf("overrides not applied: %+v", cfg)
	}
	if !cfg.MigrateOnBoot {
		t.Error("MigrateOnBoot should be true")
	}
	if cfg.ShutdownTimeout.String() != "30s" {
		t.Errorf("ShutdownTimeout = %s, want 30s", cfg.ShutdownTimeout)
	}
	if cfg.DatabaseMaxConns != 20 {
		t.Errorf("DatabaseMaxConns = %d, want 20", cfg.DatabaseMaxConns)
	}
}

func TestDeploymentThemeOverrides(t *testing.T) {
	raw := `{"--color-accent":"#6a4cf0","--color-accent-hover":"#7054f6","--color-accent-strong":"#684af0","--color-accent-contrast":"#ffffff"}`
	cfg, err := Load(envFunc(map[string]string{"PROBECTL_THEME_OVERRIDES": raw}))
	if err != nil {
		t.Fatalf("valid deployment theme: %v", err)
	}
	if got := cfg.ThemeOverrides["--color-accent"]; got != "#6a4cf0" {
		t.Fatalf("accent = %q", got)
	}
	for name, value := range map[string]string{
		"invalid JSON":    `{`,
		"unsafe token":    `{"--space-4":"99px"}`,
		"bad contrast":    `{"--color-text":"#ffffff"}`,
		"non-string JSON": `{"--color-accent":42}`,
	} {
		if _, err := Load(envFunc(map[string]string{"PROBECTL_THEME_OVERRIDES": value})); err == nil ||
			!strings.Contains(err.Error(), "PROBECTL_THEME_OVERRIDES") {
			t.Errorf("%s should fail closed, got %v", name, err)
		}
	}
}

func TestLoadReportsMultipleErrors(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"PROBECTL_LOG_LEVEL":          "verbose", // invalid enum
		"PROBECTL_LOG_FORMAT":         "xml",     // invalid enum
		"PROBECTL_HTTP_READ_TIMEOUT":  "soon",    // invalid duration
		"PROBECTL_DATABASE_MAX_CONNS": "1",       // out of range (one lease session + one worker minimum)
	}))
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"PROBECTL_LOG_LEVEL", "PROBECTL_LOG_FORMAT", "PROBECTL_HTTP_READ_TIMEOUT", "PROBECTL_DATABASE_MAX_CONNS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s; got: %v", want, err)
		}
	}
}

func TestSingletonLeaseConfig(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{"PROBECTL_SINGLETON_LEASE_INTERVAL": "750ms"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SingletonLeaseInterval != 750*time.Millisecond {
		t.Fatalf("SingletonLeaseInterval = %s, want 750ms", cfg.SingletonLeaseInterval)
	}
	_, err = Load(envFunc(map[string]string{"PROBECTL_SINGLETON_LEASE_INTERVAL": "100ms"}))
	if err == nil || !strings.Contains(err.Error(), "PROBECTL_SINGLETON_LEASE_INTERVAL") {
		t.Fatalf("unsafe lease interval must fail validation, got %v", err)
	}
}

func TestLoadMinExceedsMax(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"PROBECTL_DATABASE_MIN_CONNS": "5",
		"PROBECTL_DATABASE_MAX_CONNS": "2",
	}))
	if err == nil {
		t.Fatal("expected min>max validation error")
	}
}

// WIRE-002: a remote OTLP export target must be encrypted; a plaintext
// http:// collector (or an Insecure gRPC remote) is refused by default, while
// loopback stays usable for a co-located dev collector.
func TestOTLPExportRequiresEncryptedRemote(t *testing.T) {
	// HTTP protocol + remote http:// endpoint => refused.
	_, err := Load(envFunc(map[string]string{
		"PROBECTL_OTLP_EXPORT_PROTOCOL": "http",
		"PROBECTL_OTLP_EXPORT_ENDPOINT": "http://collector.example.com:4318",
	}))
	if err == nil || !strings.Contains(err.Error(), "PROBECTL_OTLP_EXPORT_ENDPOINT must be https") {
		t.Fatalf("remote http OTLP export must be refused; got: %v", err)
	}

	// HTTP protocol + remote https:// endpoint => allowed.
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_OTLP_EXPORT_PROTOCOL": "http",
		"PROBECTL_OTLP_EXPORT_ENDPOINT": "https://collector.example.com:4318",
	})); err != nil {
		t.Fatalf("remote https OTLP export should load: %v", err)
	}

	// HTTP protocol + loopback http:// endpoint => allowed (co-located dev).
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_OTLP_EXPORT_PROTOCOL": "http",
		"PROBECTL_OTLP_EXPORT_ENDPOINT": "http://127.0.0.1:4318",
	})); err != nil {
		t.Fatalf("loopback http OTLP export should load: %v", err)
	}

	// gRPC protocol + Insecure + remote => refused.
	_, err = Load(envFunc(map[string]string{
		"PROBECTL_OTLP_EXPORT_PROTOCOL": "grpc",
		"PROBECTL_OTLP_EXPORT_ENDPOINT": "collector.example.com:4317",
		"PROBECTL_OTLP_EXPORT_INSECURE": "true",
	}))
	if err == nil || !strings.Contains(err.Error(), "PROBECTL_OTLP_EXPORT_INSECURE is only allowed for a loopback") {
		t.Fatalf("remote insecure gRPC OTLP export must be refused; got: %v", err)
	}

	// gRPC protocol + Insecure + loopback => allowed.
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_OTLP_EXPORT_PROTOCOL": "grpc",
		"PROBECTL_OTLP_EXPORT_ENDPOINT": "localhost:4317",
		"PROBECTL_OTLP_EXPORT_INSECURE": "true",
	})); err != nil {
		t.Fatalf("loopback insecure gRPC OTLP export should load: %v", err)
	}
}

// SCALE-001: remote-write batching defaults ON in prometheus mode (the
// default production ingest path must coalesce, not POST per result); stays
// OFF for memory mode; an explicit env always wins either way.
func TestRemoteWriteBatchDefaultsOnForPrometheus(t *testing.T) {
	// prometheus mode, no explicit flag => batching ON by default.
	cfg, err := Load(envFunc(map[string]string{
		"PROBECTL_TSDB_MODE": "prometheus",
		"PROBECTL_TSDB_URL":  "http://prom:9090",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.RemoteWriteBatchEnabled {
		t.Error("prometheus mode must default RemoteWriteBatchEnabled=true (SCALE-001)")
	}

	// memory mode => batching stays OFF (no remote-write to coalesce).
	cfg, err = Load(envFunc(nil))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RemoteWriteBatchEnabled {
		t.Error("memory mode should not enable remote-write batching")
	}

	// Explicit disable wins even in prometheus mode.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_TSDB_MODE":                  "prometheus",
		"PROBECTL_TSDB_URL":                   "http://prom:9090",
		"PROBECTL_REMOTE_WRITE_BATCH_ENABLED": "false",
	}))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RemoteWriteBatchEnabled {
		t.Error("explicit PROBECTL_REMOTE_WRITE_BATCH_ENABLED=false must override the prometheus default")
	}
}

// WIRE-001: strict tenant lanes (refuse the shared pooled lane for collector
// planes) default ON under multi-tenant/regulated and OFF under single.
func TestIngestStrictTenantLanesProfileDefault(t *testing.T) {
	cfg, err := Load(envFunc(nil)) // single
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.IngestStrictTenantLanes {
		t.Error("single profile: strict tenant lanes should default OFF")
	}
	for _, p := range []string{"multi-tenant", "regulated"} {
		cfg, err := Load(envFunc(durableTenantProfileEnv(p)))
		if err != nil {
			t.Fatalf("load %s: %v", p, err)
		}
		if !cfg.IngestStrictTenantLanes {
			t.Errorf("%s profile: strict tenant lanes should default ON (WIRE-001)", p)
		}
	}
	// Production-like profiles may not reopen the shared-lane forgery surface.
	env := durableTenantProfileEnv("regulated")
	env["PROBECTL_INGEST_STRICT_TENANT_LANES"] = "false"
	if _, err = Load(envFunc(env)); err == nil || !strings.Contains(err.Error(), "PROBECTL_INGEST_STRICT_TENANT_LANES=true") {
		t.Fatalf("regulated profile must reject strict-lane disablement, got %v", err)
	}
	env = durableTenantProfileEnv("multi-tenant")
	env["PROBECTL_INGEST_STRICT_TENANT_LANES"] = "false"
	if _, err = Load(envFunc(env)); err == nil || !strings.Contains(err.Error(), "PROBECTL_INGEST_STRICT_TENANT_LANES=true") {
		t.Fatalf("multi-tenant profile must reject strict-lane disablement, got %v", err)
	}
	// Single-tenant keeps the development/lightweight escape hatch.
	env = map[string]string{"PROBECTL_INGEST_STRICT_TENANT_LANES": "false"}
	cfg, err = Load(envFunc(env))
	if err != nil {
		t.Fatalf("single profile strict-lane false should load: %v", err)
	}
	if cfg.IngestStrictTenantLanes {
		t.Error("single profile should still allow strict tenant lanes to stay off")
	}
}

func TestAuditRetentionProfileDefaultsAndWatermarkRequirements(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatalf("single load: %v", err)
	}
	if cfg.AuditRetention != 0 {
		t.Fatalf("single profile AuditRetention = %v, want keep-forever 0", cfg.AuditRetention)
	}
	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile+" default is finite and export-watermarked", func(t *testing.T) {
			cfg, err := Load(envFunc(durableTenantProfileEnv(profile)))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.AuditRetention != productionAuditRetentionDefault {
				t.Fatalf("AuditRetention = %v, want %v", cfg.AuditRetention, productionAuditRetentionDefault)
			}
			if cfg.AuditWORMDir == "" || cfg.WormSigningKeyFile == "" || !cfg.SIEMEnabled || cfg.SIEMEndpoint == "" {
				t.Fatalf("production audit retention must be backed by WORM+SIEM watermark config: %+v", cfg)
			}
		})
		t.Run(profile+" rejects disabled retention", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_AUDIT_RETENTION"] = "0"
			if _, err := Load(envFunc(env)); err == nil || !strings.Contains(err.Error(), "finite PROBECTL_AUDIT_RETENTION") {
				t.Fatalf("disabled audit retention should fail closed, got %v", err)
			}
		})
		t.Run(profile+" rejects missing export watermarks", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			delete(env, "PROBECTL_AUDIT_WORM_DIR")
			delete(env, "PROBECTL_SIEM_ENDPOINT")
			if _, err := Load(envFunc(env)); err == nil ||
				!strings.Contains(err.Error(), "PROBECTL_AUDIT_WORM_DIR") ||
				!strings.Contains(err.Error(), "PROBECTL_SIEM_ENABLED=true and PROBECTL_SIEM_ENDPOINT") {
				t.Fatalf("missing WORM/SIEM watermark config should fail closed, got %v", err)
			}
		})
	}
}

func TestLogValueRedactsPassword(t *testing.T) {
	cfg := &Config{DatabaseURL: "postgres://probectl:supersecret@db:5432/probectl?sslmode=require&password=writerquerysecret&sslpassword=writersslsecret&application_name=control"}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "config", cfg)
	out := buf.String()
	for _, secret := range []string{"supersecret", "writerquerysecret", "writersslsecret"} {
		if strings.Contains(out, secret) {
			t.Errorf("database credential leaked into logs: %s", out)
		}
	}
	if !strings.Contains(out, "xxxxx") {
		t.Errorf("expected redacted password marker; got: %s", out)
	}
	for _, metadata := range []string{"sslmode=require", "application_name=control"} {
		if !strings.Contains(out, metadata) {
			t.Errorf("non-secret database metadata %q was removed: %s", metadata, out)
		}
	}
}

func TestRedactedDatabaseURLsRedactQueryCredentials(t *testing.T) {
	cfg := &Config{
		DatabaseURL:     "postgres://writer@db:5432/probectl?sslmode=verify-full&password=writerquerysecret&application_name=control",
		DatabaseReadURL: "postgres://reader@read-db:5432/probectl?sslmode=require&sslpassword=readersslsecret&password=readerquerysecret&application_name=read-replica",
	}
	raw, err := json.Marshal(cfg.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, secret := range []string{"writerquerysecret", "readersslsecret", "readerquerysecret"} {
		if strings.Contains(out, secret) {
			t.Errorf("database credential leaked into redacted config: %s", out)
		}
	}
	for _, metadata := range []string{"sslmode=verify-full", "sslmode=require", "application_name=control", "application_name=read-replica"} {
		if !strings.Contains(out, metadata) {
			t.Errorf("non-secret database metadata %q was removed: %s", metadata, out)
		}
	}
}

func TestOTLPConfig(t *testing.T) {
	// Disabled by default.
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OTLPEnabled() {
		t.Error("OTLP should be disabled by default")
	}

	// Fully configured with legacy/bootstrap static tokens: enabled, tokens
	// parsed (whitespace trimmed).
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_OTLP_GRPC_ADDR":     ":4317",
		"PROBECTL_OTLP_HTTP_ADDR":     ":4318",
		"PROBECTL_OTLP_TLS_CERT_FILE": "/c.pem",
		"PROBECTL_OTLP_TLS_KEY_FILE":  "/k.pem",
		"PROBECTL_OTLP_TOKENS":        "tok1=tenant-a, tok2=tenant-b",
	}))
	if err != nil {
		t.Fatalf("valid OTLP config rejected: %v", err)
	}
	if !cfg.OTLPEnabled() {
		t.Error("OTLP should be enabled when address + TLS are set")
	}
	if len(cfg.OTLPTokens) != 2 || cfg.OTLPTokens["tok1"] != "tenant-a" || cfg.OTLPTokens["tok2"] != "tenant-b" {
		t.Errorf("OTLPTokens = %v, want 2 trimmed entries", cfg.OTLPTokens)
	}

	// WIRE-003: DB-backed tokens can be the only token source. The receiver
	// starts with address+TLS and no static PROBECTL_OTLP_TOKENS; auth still
	// fails closed per request until the admin API creates DB tokens.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_OTLP_GRPC_ADDR":     ":4317",
		"PROBECTL_OTLP_TLS_CERT_FILE": "/c.pem",
		"PROBECTL_OTLP_TLS_KEY_FILE":  "/k.pem",
	}))
	if err != nil {
		t.Fatalf("DB-only OTLP config rejected: %v", err)
	}
	if !cfg.OTLPEnabled() {
		t.Error("OTLP should be enabled with address + TLS even when static tokens are absent")
	}
	if len(cfg.OTLPTokens) != 0 {
		t.Errorf("OTLPTokens = %v, want no static tokens", cfg.OTLPTokens)
	}

	// An address without TLS fails closed.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_OTLP_GRPC_ADDR": ":4317"})); err == nil || !strings.Contains(err.Error(), "OTLP") {
		t.Errorf("OTLP address without TLS should fail, got %v", err)
	}

	// A malformed token entry is reported.
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_OTLP_GRPC_ADDR":     ":4317",
		"PROBECTL_OTLP_TLS_CERT_FILE": "/c.pem",
		"PROBECTL_OTLP_TLS_KEY_FILE":  "/k.pem",
		"PROBECTL_OTLP_TOKENS":        "missing-equals",
	})); err == nil || !strings.Contains(err.Error(), "PROBECTL_OTLP_TOKENS") {
		t.Errorf("a malformed OTLP token should fail with a tokens error, got %v", err)
	}

	// WIRE-004: first-party OTLP freshness is opt-in and requires a real key.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_OTLP_GRPC_ADDR":          ":4317",
		"PROBECTL_OTLP_TLS_CERT_FILE":      "/c.pem",
		"PROBECTL_OTLP_TLS_KEY_FILE":       "/k.pem",
		"PROBECTL_OTLP_FRESHNESS_HMAC_KEY": testSessionHMACKeyHex,
		"PROBECTL_OTLP_FRESHNESS_WINDOW":   "2m",
	}))
	if err != nil {
		t.Fatalf("OTLP freshness config rejected: %v", err)
	}
	if got := len(cfg.OTLPFreshnessHMACKey); got != crypto.KeySize {
		t.Fatalf("OTLPFreshnessHMACKey length = %d, want %d", got, crypto.KeySize)
	}
	if cfg.OTLPFreshnessWindow != 2*time.Minute {
		t.Fatalf("OTLPFreshnessWindow = %s, want 2m", cfg.OTLPFreshnessWindow)
	}
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_OTLP_GRPC_ADDR":          ":4317",
		"PROBECTL_OTLP_TLS_CERT_FILE":      "/c.pem",
		"PROBECTL_OTLP_TLS_KEY_FILE":       "/k.pem",
		"PROBECTL_OTLP_FRESHNESS_HMAC_KEY": "abcd",
	})); err == nil || !strings.Contains(err.Error(), "PROBECTL_OTLP_FRESHNESS_HMAC_KEY") {
		t.Errorf("short OTLP freshness key should fail, got %v", err)
	}
}

func TestAIConfig(t *testing.T) {
	// Default: the in-process, air-gapped built-in model (no external endpoint).
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AIModelProvider != "builtin" || cfg.AIModelEnabled() {
		t.Errorf("default should be the air-gapped builtin model, got provider=%q enabled=%v", cfg.AIModelProvider, cfg.AIModelEnabled())
	}
	if cfg.AIMaxEvidence != 50 {
		t.Errorf("AIMaxEvidence default = %d, want 50", cfg.AIMaxEvidence)
	}

	// A local Ollama endpoint enables the external-model path.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_AI_MODEL_PROVIDER": "ollama",
		"PROBECTL_AI_MODEL_ENDPOINT": "http://localhost:11434",
		"PROBECTL_AI_MODEL_NAME":     "llama3.1",
	}))
	if err != nil {
		t.Fatalf("valid ollama config rejected: %v", err)
	}
	if !cfg.AIModelEnabled() {
		t.Error("ollama provider should enable an external model")
	}
	if cfg.AIEgressAck != "" {
		t.Errorf("local loopback model should not need egress ack, got %q", cfg.AIEgressAck)
	}

	// A remote HTTPS endpoint still needs the explicit data-egress ack.
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_AI_MODEL_PROVIDER": "openai",
		"PROBECTL_AI_MODEL_ENDPOINT": "https://model.example.com",
		"PROBECTL_AI_MODEL_NAME":     "gpt-test",
	})); err == nil || !strings.Contains(err.Error(), "PROBECTL_AI_EGRESS_ACK") {
		t.Errorf("remote https ai endpoint without egress ack should fail closed, got %v", err)
	}

	// A remote HTTPS endpoint is allowed only after the explicit data-egress ack.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_AI_MODEL_PROVIDER": "openai",
		"PROBECTL_AI_MODEL_ENDPOINT": "https://model.example.com",
		"PROBECTL_AI_MODEL_NAME":     "gpt-test",
		"PROBECTL_AI_EGRESS_ACK":     AIEgressAckPhrase,
	}))
	if err != nil {
		t.Fatalf("remote https ai config with egress ack rejected: %v", err)
	}
	if !cfg.AIModelEnabled() {
		t.Error("remote https provider should enable an external model")
	}

	// The egress ack is not a plaintext exemption: remote endpoints must be HTTPS.
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_AI_MODEL_PROVIDER": "openai",
		"PROBECTL_AI_MODEL_ENDPOINT": "http://model.example.com",
		"PROBECTL_AI_MODEL_NAME":     "gpt-test",
		"PROBECTL_AI_EGRESS_ACK":     AIEgressAckPhrase,
	})); err == nil || !strings.Contains(err.Error(), "PROBECTL_AI_MODEL_ENDPOINT must be https://") {
		t.Errorf("remote plaintext ai endpoint should fail closed, got %v", err)
	}

	// A non-builtin provider without an endpoint fails closed.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_AI_MODEL_PROVIDER": "openai"})); err == nil || !strings.Contains(err.Error(), "PROBECTL_AI_MODEL_ENDPOINT") {
		t.Errorf("provider without endpoint should fail, got %v", err)
	}
	// An unknown provider is rejected by the enum.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_AI_MODEL_PROVIDER": "skynet"})); err == nil {
		t.Error("unknown provider should be rejected")
	}
}

func TestMCPConfig(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MCPEnabled() {
		t.Error("MCP should be disabled by default")
	}
	if cfg.MCPRatePerMin != 120 {
		t.Errorf("MCPRatePerMin default = %d, want 120", cfg.MCPRatePerMin)
	}

	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_MCP_HTTP_ADDR":     ":8090",
		"PROBECTL_MCP_TLS_CERT_FILE": "/c.pem",
		"PROBECTL_MCP_TLS_KEY_FILE":  "/k.pem",
		"PROBECTL_MCP_RATE_PER_MIN":  "60",
	}))
	if err != nil {
		t.Fatalf("valid MCP config rejected: %v", err)
	}
	if !cfg.MCPEnabled() {
		t.Error("MCP should be enabled with an address + TLS")
	}
	if cfg.MCPRatePerMin != 60 {
		t.Errorf("MCPRatePerMin = %d, want 60", cfg.MCPRatePerMin)
	}

	// An address without TLS fails closed (never plaintext — guardrail 12).
	if _, err := Load(envFunc(map[string]string{"PROBECTL_MCP_HTTP_ADDR": ":8090"})); err == nil || !strings.Contains(err.Error(), "MCP") {
		t.Errorf("MCP address without TLS should fail, got %v", err)
	}
}

func TestThreatTLSConfig(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSExpiryWarning <= 0 {
		t.Error("the TLS expiry window should default to a positive duration")
	}
	if cfg.CTEnabled {
		t.Error("CT correlation should be off by default (AUP / sovereignty)")
	}
	if cfg.CTEndpoint != "https://crt.sh" {
		t.Errorf("CT endpoint default = %q, want https://crt.sh", cfg.CTEndpoint)
	}

	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_TRUSTCTL_URL":       "https://trustctl.example",
		"PROBECTL_TLS_EXPIRY_WARNING": "240h",
		"PROBECTL_CT_ENABLED":         "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrustctlURL != "https://trustctl.example" || !cfg.CTEnabled || cfg.TLSExpiryWarning.Hours() != 240 {
		t.Errorf("threat config = %+v", cfg)
	}

	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_CT_ENABLED":  "true",
		"PROBECTL_CT_ENDPOINT": "http://crt.example",
	})); err == nil || !strings.Contains(err.Error(), "PROBECTL_CT_ENDPOINT") {
		t.Fatalf("remote plaintext CT endpoint should fail closed, got %v", err)
	}
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_CT_ENABLED":  "true",
		"PROBECTL_CT_ENDPOINT": "http://127.0.0.1:8080",
	})); err != nil {
		t.Fatalf("loopback plaintext CT fixture should be allowed: %v", err)
	}
}

func TestSIEMRejectsPlaintextRemote(t *testing.T) {
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_SIEM_ENABLED":  "true",
		"PROBECTL_SIEM_ENDPOINT": "http://siem.example/ingest",
	})); err == nil || !strings.Contains(err.Error(), "PROBECTL_SIEM_ENDPOINT") {
		t.Fatalf("remote plaintext SIEM endpoint should fail closed, got %v", err)
	}
	if _, err := Load(envFunc(map[string]string{
		"PROBECTL_SIEM_ENABLED":  "true",
		"PROBECTL_SIEM_ENDPOINT": "http://localhost:18080/ingest",
	})); err != nil {
		t.Fatalf("loopback plaintext SIEM fixture should be allowed: %v", err)
	}
}
