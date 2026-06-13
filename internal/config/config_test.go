// SPDX-License-Identifier: LicenseRef-probectl-TBD

package config

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func envFunc(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
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
	if cfg.DatabaseMaxConns != 10 {
		t.Errorf("DatabaseMaxConns = %d, want 10", cfg.DatabaseMaxConns)
	}
}

// TENANT-004: DB-enforced ClickHouse tenant isolation must default ON across
// ALL four telemetry planes in the multi-tenant/regulated profile (defense in
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
		} {
			if on {
				t.Errorf("single profile: %s CH scoping defaulted ON, want OFF", name)
			}
		}
	})
	for _, profile := range []string{"multi-tenant", "regulated"} {
		t.Run(profile+" enables DB-layer isolation on every plane", func(t *testing.T) {
			cfg, err := Load(envFunc(map[string]string{"PROBECTL_DEPLOYMENT_PROFILE": profile}))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			for name, on := range map[string]bool{
				"flow": cfg.FlowCHTenantScoping, "otel": cfg.OTelCHTenantScoping,
				"ebpf": cfg.EBPFCHTenantScoping, "path": cfg.PathCHTenantScoping,
			} {
				if !on {
					t.Errorf("%s profile: %s CH scoping defaulted OFF, want ON (DB-layer isolation)", profile, name)
				}
			}
		})
	}
	t.Run("explicit env overrides the profile default", func(t *testing.T) {
		cfg, err := Load(envFunc(map[string]string{
			"PROBECTL_DEPLOYMENT_PROFILE":      "regulated",
			"PROBECTL_OTELSTORE_TENANT_SCOPING": "false",
		}))
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.OTelCHTenantScoping {
			t.Error("explicit PROBECTL_OTELSTORE_TENANT_SCOPING=false did not override the profile default")
		}
		if !cfg.FlowCHTenantScoping {
			t.Error("flow scoping should still be ON from the regulated profile")
		}
	})
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

	// Kafka + Prometheus with their required settings (brokers are trimmed).
	// Kafka requires TLS (U-010) — the happy path enables it.
	cfg, err = Load(envFunc(map[string]string{
		"PROBECTL_BUS_MODE":        "kafka",
		"PROBECTL_BUS_BROKERS":     "b1:9092, b2:9092",
		"PROBECTL_BUS_TLS_ENABLED": "true",
		"PROBECTL_TSDB_MODE":       "prometheus",
		"PROBECTL_TSDB_URL":        "http://prom:9090",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.BusBrokers) != 2 || cfg.BusBrokers[0] != "b1:9092" || cfg.BusBrokers[1] != "b2:9092" {
		t.Errorf("BusBrokers = %v, want [b1:9092 b2:9092]", cfg.BusBrokers)
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

func TestLoadReportsMultipleErrors(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"PROBECTL_LOG_LEVEL":          "verbose", // invalid enum
		"PROBECTL_LOG_FORMAT":         "xml",     // invalid enum
		"PROBECTL_HTTP_READ_TIMEOUT":  "soon",    // invalid duration
		"PROBECTL_DATABASE_MAX_CONNS": "0",       // out of range (min 1)
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

func TestLoadMinExceedsMax(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"PROBECTL_DATABASE_MIN_CONNS": "5",
		"PROBECTL_DATABASE_MAX_CONNS": "2",
	}))
	if err == nil {
		t.Fatal("expected min>max validation error")
	}
}

func TestLogValueRedactsPassword(t *testing.T) {
	cfg := &Config{DatabaseURL: "postgres://probectl:supersecret@db:5432/probectl"}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("cfg", "config", cfg)
	out := buf.String()
	if strings.Contains(out, "supersecret") {
		t.Errorf("password leaked into logs: %s", out)
	}
	if !strings.Contains(out, "xxxxx") {
		t.Errorf("expected redacted password marker; got: %s", out)
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

	// Fully configured: enabled, tokens parsed (whitespace trimmed).
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
		t.Error("OTLP should be enabled when address + TLS + tokens are all set")
	}
	if len(cfg.OTLPTokens) != 2 || cfg.OTLPTokens["tok1"] != "tenant-a" || cfg.OTLPTokens["tok2"] != "tenant-b" {
		t.Errorf("OTLPTokens = %v, want 2 trimmed entries", cfg.OTLPTokens)
	}

	// An address without TLS + tokens fails closed.
	if _, err := Load(envFunc(map[string]string{"PROBECTL_OTLP_GRPC_ADDR": ":4317"})); err == nil || !strings.Contains(err.Error(), "OTLP") {
		t.Errorf("OTLP address without TLS/tokens should fail, got %v", err)
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
}
