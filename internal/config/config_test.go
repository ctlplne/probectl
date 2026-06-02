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
	cfg, err = Load(envFunc(map[string]string{
		"NETCTL_BUS_MODE":    "kafka",
		"NETCTL_BUS_BROKERS": "b1:9092, b2:9092",
		"NETCTL_TSDB_MODE":   "prometheus",
		"NETCTL_TSDB_URL":    "http://prom:9090",
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.BusBrokers) != 2 || cfg.BusBrokers[0] != "b1:9092" || cfg.BusBrokers[1] != "b2:9092" {
		t.Errorf("BusBrokers = %v, want [b1:9092 b2:9092]", cfg.BusBrokers)
	}

	// kafka without brokers and prometheus without a URL must both fail.
	if _, err := Load(envFunc(map[string]string{"NETCTL_BUS_MODE": "kafka"})); err == nil || !strings.Contains(err.Error(), "NETCTL_BUS_BROKERS") {
		t.Errorf("kafka without brokers should fail with a brokers error, got %v", err)
	}
	if _, err := Load(envFunc(map[string]string{"NETCTL_TSDB_MODE": "prometheus"})); err == nil || !strings.Contains(err.Error(), "NETCTL_TSDB_URL") {
		t.Errorf("prometheus without a URL should fail with a URL error, got %v", err)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(envFunc(map[string]string{
		"NETCTL_HTTP_ADDR":          ":9000",
		"NETCTL_LOG_LEVEL":          "debug",
		"NETCTL_LOG_FORMAT":         "text",
		"NETCTL_MIGRATE_ON_BOOT":    "true",
		"NETCTL_SHUTDOWN_TIMEOUT":   "30s",
		"NETCTL_DATABASE_MAX_CONNS": "20",
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
		"NETCTL_LOG_LEVEL":          "verbose", // invalid enum
		"NETCTL_LOG_FORMAT":         "xml",     // invalid enum
		"NETCTL_HTTP_READ_TIMEOUT":  "soon",    // invalid duration
		"NETCTL_DATABASE_MAX_CONNS": "0",       // out of range (min 1)
	}))
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"NETCTL_LOG_LEVEL", "NETCTL_LOG_FORMAT", "NETCTL_HTTP_READ_TIMEOUT", "NETCTL_DATABASE_MAX_CONNS"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %s; got: %v", want, err)
		}
	}
}

func TestLoadMinExceedsMax(t *testing.T) {
	_, err := Load(envFunc(map[string]string{
		"NETCTL_DATABASE_MIN_CONNS": "5",
		"NETCTL_DATABASE_MAX_CONNS": "2",
	}))
	if err == nil {
		t.Fatal("expected min>max validation error")
	}
}

func TestLogValueRedactsPassword(t *testing.T) {
	cfg := &Config{DatabaseURL: "postgres://netctl:supersecret@db:5432/netctl"}
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
		"NETCTL_OTLP_GRPC_ADDR":     ":4317",
		"NETCTL_OTLP_HTTP_ADDR":     ":4318",
		"NETCTL_OTLP_TLS_CERT_FILE": "/c.pem",
		"NETCTL_OTLP_TLS_KEY_FILE":  "/k.pem",
		"NETCTL_OTLP_TOKENS":        "tok1=tenant-a, tok2=tenant-b",
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
	if _, err := Load(envFunc(map[string]string{"NETCTL_OTLP_GRPC_ADDR": ":4317"})); err == nil || !strings.Contains(err.Error(), "OTLP") {
		t.Errorf("OTLP address without TLS/tokens should fail, got %v", err)
	}

	// A malformed token entry is reported.
	if _, err := Load(envFunc(map[string]string{
		"NETCTL_OTLP_GRPC_ADDR":     ":4317",
		"NETCTL_OTLP_TLS_CERT_FILE": "/c.pem",
		"NETCTL_OTLP_TLS_KEY_FILE":  "/k.pem",
		"NETCTL_OTLP_TOKENS":        "missing-equals",
	})); err == nil || !strings.Contains(err.Error(), "NETCTL_OTLP_TOKENS") {
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
		"NETCTL_AI_MODEL_PROVIDER": "ollama",
		"NETCTL_AI_MODEL_ENDPOINT": "http://localhost:11434",
		"NETCTL_AI_MODEL_NAME":     "llama3.1",
	}))
	if err != nil {
		t.Fatalf("valid ollama config rejected: %v", err)
	}
	if !cfg.AIModelEnabled() {
		t.Error("ollama provider should enable an external model")
	}

	// A non-builtin provider without an endpoint fails closed.
	if _, err := Load(envFunc(map[string]string{"NETCTL_AI_MODEL_PROVIDER": "openai"})); err == nil || !strings.Contains(err.Error(), "NETCTL_AI_MODEL_ENDPOINT") {
		t.Errorf("provider without endpoint should fail, got %v", err)
	}
	// An unknown provider is rejected by the enum.
	if _, err := Load(envFunc(map[string]string{"NETCTL_AI_MODEL_PROVIDER": "skynet"})); err == nil {
		t.Error("unknown provider should be rejected")
	}
}
