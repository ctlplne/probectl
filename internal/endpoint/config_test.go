// SPDX-License-Identifier: LicenseRef-probectl-TBD

package endpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	c := Default()
	if c.Bus.Mode != "memory" || c.Interval <= 0 || len(c.Targets) == 0 {
		t.Fatalf("unexpected defaults: %+v", c)
	}
	if !c.Privacy.CollectSSID || c.Privacy.CollectBSSID {
		t.Errorf("default privacy should be balanced (SSID on, BSSID off)")
	}
}

func TestLoadYAMLAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint.yml")
	yml := `apiVersion: probectl.io/endpoint/v1
tenant_id: acme
agent_id: kiosk-1
interval: 30s
targets:
  - https://portal.acme
  - https://1.1.1.1
privacy:
  collect_ssid: true
  collect_bssid: true
thresholds:
  wifi_weak_rssi_dbm: -70
`
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.TenantID != "acme" || c.AgentID != "kiosk-1" || len(c.Targets) != 2 {
		t.Errorf("yaml not applied: %+v", c)
	}
	if !c.Privacy.CollectBSSID {
		t.Errorf("privacy yaml not applied")
	}
	if c.Thresholds.WiFiWeakRSSIDBm != -70 {
		t.Errorf("threshold yaml not applied: %v", c.Thresholds.WiFiWeakRSSIDBm)
	}
}

func TestLoadRequiresVersionAndRejectsUnknownKeys(t *testing.T) {
	missingVersion := writeEndpointConfig(t, `
tenant_id: acme
targets:
  - https://portal.acme
`)
	_, err := Load(missingVersion)
	if err == nil || !strings.Contains(err.Error(), "apiVersion is required") {
		t.Fatalf("missing apiVersion should fail, got %v", err)
	}

	unknown := writeEndpointConfig(t, `
apiVersion: probectl.io/endpoint/v1
tenant_id: acme
old_removed_key: true
targets:
  - https://portal.acme
`)
	_, err = Load(unknown)
	if err == nil || !strings.Contains(err.Error(), "field old_removed_key not found") {
		t.Fatalf("unknown key should fail strict YAML decode, got %v", err)
	}
}

func TestLoadAcceptsSchemaVersionAlias(t *testing.T) {
	path := writeEndpointConfig(t, `
schema_version: 1
tenant_id: acme
targets:
  - https://portal.acme
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("schema_version alias should load: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
	}
}

func TestShippedEndpointConfigLoadsStrictly(t *testing.T) {
	t.Setenv("PROBECTL_ENDPOINT_TENANT_ID", "t-packaged")
	cfg, err := Load(filepath.Join("..", "..", "deploy", "packaging", "config", "endpoint.yaml"))
	if err != nil {
		t.Fatalf("load shipped config: %v", err)
	}
	if cfg.APIVersion != ConfigAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", cfg.APIVersion, ConfigAPIVersion)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	c := Default()
	env := map[string]string{
		"PROBECTL_ENDPOINT_TENANT_ID":           "t9",
		"PROBECTL_ENDPOINT_TARGETS":             "https://a, https://b ,https://c",
		"PROBECTL_ENDPOINT_COLLECT_BSSID":       "true",
		"PROBECTL_ENDPOINT_COLLECT_PUBLIC_HOPS": "true",
		"PROBECTL_ENDPOINT_INTERVAL":            "15s",
	}
	c.applyEnv(func(k string) string { return env[k] })
	if c.TenantID != "t9" {
		t.Errorf("tenant env not applied")
	}
	if len(c.Targets) != 3 {
		t.Errorf("targets env split wrong: %+v", c.Targets)
	}
	if !c.Privacy.CollectBSSID || !c.Privacy.CollectPublicHops {
		t.Errorf("privacy env toggles not applied")
	}
	if c.Interval.String() != "15s" {
		t.Errorf("interval env not applied: %v", c.Interval)
	}
}

func writeEndpointConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "endpoint.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateErrors(t *testing.T) {
	t.Run("missing tenant", func(t *testing.T) {
		c := Default()
		if err := c.validate(); err == nil {
			t.Errorf("tenant_id is required")
		}
	})
	t.Run("bad bus mode", func(t *testing.T) {
		c := Default()
		c.TenantID = "t"
		c.Bus.Mode = "carrier-pigeon"
		if err := c.validate(); err == nil {
			t.Errorf("invalid bus mode should fail")
		}
	})
	t.Run("kafka needs brokers", func(t *testing.T) {
		c := Default()
		c.TenantID = "t"
		c.Bus.Mode = "kafka"
		if err := c.validate(); err == nil {
			t.Errorf("kafka without brokers should fail")
		}
	})
	t.Run("no targets", func(t *testing.T) {
		c := Default()
		c.TenantID = "t"
		c.Targets = nil
		if err := c.validate(); err == nil {
			t.Errorf("at least one target is required")
		}
	})
}
