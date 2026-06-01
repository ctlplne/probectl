package ebpf

import (
	"path/filepath"
	"testing"
	"time"
)

func TestConfigLoadYAMLAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ebpf.yaml")
	writeFile(t, path, "tenant_id: t-yaml\nflush_interval: 5s\nbus:\n  mode: memory\n")

	t.Setenv("NETCTL_EBPF_TENANT_ID", "t-env")
	t.Setenv("NETCTL_EBPF_FLUSH_INTERVAL", "2s")

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
}
