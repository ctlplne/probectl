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
