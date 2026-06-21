// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigLoadRequiresVersionAndRejectsUnknownKeys(t *testing.T) {
	missingVersion := writeDeviceConfig(t, `
tenant_id: t
devices:
  - address: 192.0.2.1
    transport: snmpv2c
    credential: core
`)
	_, err := Load(missingVersion)
	if err == nil || !strings.Contains(err.Error(), "apiVersion is required") {
		t.Fatalf("missing apiVersion should fail, got %v", err)
	}

	unknown := writeDeviceConfig(t, `
apiVersion: probectl.io/device-agent/v1
tenant_id: t
old_removed_key: true
devices:
  - address: 192.0.2.1
    transport: snmpv2c
    credential: core
`)
	_, err = Load(unknown)
	if err == nil || !strings.Contains(err.Error(), "field old_removed_key not found") {
		t.Fatalf("unknown key should fail strict YAML decode, got %v", err)
	}
}

func TestConfigLoadAcceptsSchemaVersionAlias(t *testing.T) {
	path := writeDeviceConfig(t, `
schema_version: 1
tenant_id: t
devices:
  - address: 192.0.2.1
    transport: snmpv2c
    credential: core
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("schema_version alias should load: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
	}
}

func TestShippedDeviceConfigsLoadStrictly(t *testing.T) {
	t.Setenv("PROBECTL_DEVICE_TENANT", "t-packaged")
	for _, path := range []string{
		filepath.Join("..", "..", "deploy", "agent", "probectl-device-agent.example.yml"),
		filepath.Join("..", "..", "deploy", "packaging", "config", "device-agent.yaml"),
	} {
		t.Run(path, func(t *testing.T) {
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("load shipped config: %v", err)
			}
			if cfg.APIVersion != ConfigAPIVersion {
				t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
			}
		})
	}
}

func writeDeviceConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "device.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
