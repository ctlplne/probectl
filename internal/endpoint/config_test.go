// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	c := Default()
	// Updated for PLAT-20 / G7-2: the default ships NO probe targets (was
	// Cloudflare/Google anycast, a default outbound phone-home). The old
	// assertion required a non-empty target list, which encoded that beacon.
	if c.Bus.Mode != "memory" || c.Interval <= 0 || len(c.Targets) != 0 {
		t.Fatalf("unexpected defaults (no external probe targets must ship by default, G7-2): %+v", c)
	}
	if !c.Privacy.CollectSSID || c.Privacy.CollectBSSID {
		t.Errorf("default privacy should be balanced (SSID on, BSSID off)")
	}
}

// TestDefaultShipsNoExternalTargets locks in the endpoint agent's no-phone-home
// guarantee (docs/guardrails.md G7-2, finding PLAT-20): neither the built-in
// defaults nor a Load() with no configured targets may contact an external
// probe host, so an agent installed with no explicit targets beacons nowhere
// off-device until an operator configures it.
func TestDefaultShipsNoExternalTargets(t *testing.T) {
	// forbidden are the external anycast hosts that used to ship as defaults and
	// would silently probe out every interval.
	forbidden := []string{"1.1.1.1", "www.google.com"}
	assertNoExternalTargets := func(t *testing.T, where string, targets []string) {
		t.Helper()
		for _, tgt := range targets {
			for _, host := range forbidden {
				if strings.Contains(tgt, host) {
					t.Errorf("%s ships external probe target %q (host %q) — a default outbound beacon violates no-phone-home (docs/guardrails.md G7-2)", where, tgt, host)
				}
			}
		}
	}

	t.Run("Default has no targets", func(t *testing.T) {
		if got := Default().Targets; len(got) != 0 {
			t.Errorf("Default().Targets = %v, want none (no-phone-home, G7-2)", got)
		}
		assertNoExternalTargets(t, "Default().Targets", Default().Targets)
	})

	t.Run("Load with no configured targets stays empty", func(t *testing.T) {
		t.Setenv("PROBECTL_ENDPOINT_TENANT_ID", "t-no-targets")
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load with no targets must succeed (agent probes nothing until configured), got %v", err)
		}
		if len(cfg.Targets) != 0 {
			t.Errorf("Load() with no configured targets = %v, want none", cfg.Targets)
		}
		assertNoExternalTargets(t, "Load() with no configured targets", cfg.Targets)
	})

	// Non-vacuity: an explicitly configured target is still honored end to end,
	// so this test cannot pass merely because targets are always dropped.
	t.Run("explicit target is honored", func(t *testing.T) {
		t.Setenv("PROBECTL_ENDPOINT_TENANT_ID", "t-explicit")
		t.Setenv("PROBECTL_ENDPOINT_TARGETS", "https://portal.internal")
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("Load with an explicit target: %v", err)
		}
		if len(cfg.Targets) != 1 || cfg.Targets[0] != "https://portal.internal" {
			t.Fatalf("explicit target not honored by Load(): %v", cfg.Targets)
		}
	})
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

func TestLoadBoundsConfigFile(t *testing.T) {
	const limit = 1 << 20
	valid := []byte("apiVersion: " + ConfigAPIVersion + "\ntenant_id: acme\n")
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
			path := filepath.Join(t.TempDir(), "endpoint.yml")
			if err := os.WriteFile(path, pad(tc.size), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
					t.Fatalf("one-past-maximum endpoint config error = %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("maximum-sized endpoint config rejected: %v", err)
			}
		})
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
	t.Run("no targets is accepted", func(t *testing.T) {
		// Updated for PLAT-20 / G7-2: validate() used to reject an empty target
		// list ("at least one target is required"), the very rule that forced an
		// external default to exist. It now accepts none — the agent starts and
		// simply probes nothing off-device until an operator configures targets.
		c := Default()
		c.TenantID = "t"
		c.Targets = nil
		if err := c.validate(); err != nil {
			t.Errorf("empty targets must be accepted (probe nothing until configured, G7-2), got %v", err)
		}
	})
}
