// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigLoadYAMLAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ebpf.yaml")
	writeFile(t, path, "apiVersion: "+ConfigAPIVersion+"\ntenant_id: t-yaml\nflush_interval: 5s\nbus:\n  mode: memory\n")

	t.Setenv("PROBECTL_EBPF_TENANT_ID", "t-env")
	t.Setenv("PROBECTL_EBPF_FLUSH_INTERVAL", "2s")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TenantID != "t-env" {
		t.Errorf("tenant = %q, want env override t-env", cfg.TenantID)
	}
	if cfg.FlushInterval != 2*time.Second {
		t.Errorf("flush = %v, want 2s", cfg.FlushInterval)
	}
}

func TestConfigRequiresVersionAndRejectsUnknownKeys(t *testing.T) {
	missingVersion := filepath.Join(t.TempDir(), "ebpf.yaml")
	writeFile(t, missingVersion, "tenant_id: t\nbus:\n  mode: memory\n")
	_, err := Load(missingVersion)
	if err == nil || !strings.Contains(err.Error(), "apiVersion is required") {
		t.Fatalf("missing apiVersion should fail, got %v", err)
	}

	unknown := filepath.Join(t.TempDir(), "ebpf.yaml")
	writeFile(t, unknown, "apiVersion: "+ConfigAPIVersion+"\ntenant_id: t\nold_removed_key: true\nbus:\n  mode: memory\n")
	_, err = Load(unknown)
	if err == nil || !strings.Contains(err.Error(), "field old_removed_key not found") {
		t.Fatalf("unknown key should fail strict YAML decode, got %v", err)
	}
}

func TestConfigAcceptsSchemaVersionAlias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ebpf.yaml")
	writeFile(t, path, "schema_version: 1\ntenant_id: t\nbus:\n  mode: memory\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("schema_version alias should load: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
	}
}

func TestShippedEBPFConfigExampleLoadsStrictly(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "deploy", "agent", "probectl-ebpf-agent.example.yml"))
	if err != nil {
		t.Fatalf("load shipped config: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
	}
}

func TestConfigValidate(t *testing.T) {
	base := func() *Config {
		return &Config{TenantID: "t", Bus: BusConfig{Mode: "memory"}, FlushInterval: time.Second}
	}
	if err := base().validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	noTenant := base()
	noTenant.TenantID = ""
	if err := noTenant.validate(); err == nil {
		t.Error("missing tenant_id should fail")
	}

	badBus := base()
	badBus.Bus.Mode = "rabbit"
	if err := badBus.validate(); err == nil {
		t.Error("invalid bus mode should fail")
	}

	kafkaNoBrokers := base()
	kafkaNoBrokers.Bus = BusConfig{Mode: "kafka"}
	if err := kafkaNoBrokers.validate(); err == nil {
		t.Error("kafka without brokers should fail")
	}

	// EBPF-005: the ring buffer has an upper bound.
	atMax := base()
	atMax.RingBufferBytes = maxRingBufferBytes
	if err := atMax.validate(); err != nil {
		t.Errorf("ring_buffer_bytes at the max (%d) should be accepted: %v", maxRingBufferBytes, err)
	}
	overMax := base()
	overMax.RingBufferBytes = maxRingBufferBytes + 1
	if err := overMax.validate(); err == nil {
		t.Errorf("ring_buffer_bytes over the max (%d) should fail validation", overMax.RingBufferBytes)
	}
}
