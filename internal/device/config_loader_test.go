// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBoundsConfigFile(t *testing.T) {
	const limit = 1 << 20
	valid := []byte("apiVersion: " + ConfigAPIVersion + "\ntenant_id: t\ndevices:\n  - address: 192.0.2.1\n    transport: snmpv2c\n    credential: core\n")
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
			path := filepath.Join(t.TempDir(), "device.yml")
			if err := os.WriteFile(path, pad(tc.size), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
					t.Fatalf("one-past-maximum device config error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("maximum-sized device config rejected: %v", err)
			}
		})
	}
}

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

func TestConfigLoadAllowsTrapOnlyAuthenticatedListener(t *testing.T) {
	path := writeDeviceConfig(t, `
apiVersion: probectl.io/device-agent/v1
tenant_id: t
traps:
  enabled: true
  sources:
    - name: core-switches
      address: 192.0.2.10
      transport: snmpv2c
      credential: core-traps
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("trap-only config should load: %v", err)
	}
	if cfg.Traps.Listen != ":9162" {
		t.Fatalf("trap listen default = %q, want :9162", cfg.Traps.Listen)
	}
	if len(cfg.Devices) != 0 || len(cfg.Traps.Sources) != 1 {
		t.Fatalf("loaded config = %+v", cfg)
	}
}

func TestConfigLoadRejectsTrapListenerWithoutAuthenticatedSources(t *testing.T) {
	path := writeDeviceConfig(t, `
apiVersion: probectl.io/device-agent/v1
tenant_id: t
traps:
  enabled: true
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "traps.sources requires at least one authenticated source") {
		t.Fatalf("unauthenticated trap listener should fail, got %v", err)
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
