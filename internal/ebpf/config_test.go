// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadBoundsConfigFile(t *testing.T) {
	const limit = 1 << 20
	valid := []byte("apiVersion: " + ConfigAPIVersion + "\ntenant_id: t\n")
	pad := func(size int) []byte {
		t.Helper()
		if size < len(valid)+2 {
			t.Fatalf("fixture size %d is too small", size)
		}
		return append(append(append([]byte{}, valid...), '\n', '#'), bytes.Repeat([]byte{'x'}, size-len(valid)-2)...)
	}

	for _, tc := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "maximum", size: limit},
		{name: "one past maximum", size: limit + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ebpf.yml")
			writeFile(t, path, string(pad(tc.size)))
			_, err := Load(path)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
					t.Fatalf("one-past-maximum ebpf config error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("maximum-sized ebpf config rejected: %v", err)
			}
		})
	}
}

func TestConfigLoadYAMLAndEnvOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ebpf.yaml")
	writeFile(t, path, "apiVersion: "+ConfigAPIVersion+"\ntenant_id: t-yaml\nflush_interval: 5s\nbus:\n  mode: memory\n")

	t.Setenv("PROBECTL_EBPF_TENANT_ID", "t-env")
	t.Setenv("PROBECTL_EBPF_FLUSH_INTERVAL", "2s")
	t.Setenv("PROBECTL_EBPF_L7_RING_BUFFER_BYTES", "33554432")
	t.Setenv("PROBECTL_EBPF_L7_IDENTITY_HEADER_FRAGMENTS", "member, viewer ")
	t.Setenv("PROBECTL_EBPF_L7_HASH_ALL_HEADER_VALUES", "true")

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
	if cfg.L7RingBufferBytes != 33_554_432 {
		t.Errorf("l7 ring = %d, want 33554432", cfg.L7RingBufferBytes)
	}
	if got := strings.Join(cfg.L7CaptureIdentityHeaderFragments, ","); got != "member,viewer" {
		t.Errorf("identity header fragments = %q, want member,viewer", got)
	}
	if !cfg.L7CaptureHashAllHeaderValues {
		t.Error("hash-all header values env override should be true")
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
	l7AtMax := base()
	l7AtMax.L7RingBufferBytes = maxRingBufferBytes
	if err := l7AtMax.validate(); err != nil {
		t.Errorf("l7_ring_buffer_bytes at the max (%d) should be accepted: %v", maxRingBufferBytes, err)
	}
	l7OverMax := base()
	l7OverMax.L7RingBufferBytes = maxRingBufferBytes + 1
	if err := l7OverMax.validate(); err == nil {
		t.Errorf("l7_ring_buffer_bytes over the max (%d) should fail validation", l7OverMax.L7RingBufferBytes)
	}
}
