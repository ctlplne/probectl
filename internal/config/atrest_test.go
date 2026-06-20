// SPDX-License-Identifier: LicenseRef-probectl-TBD

package config

import "testing"

// KEYS-001/TENANT-106: at-rest encryption is the default serve posture; the
// only keyless path is the explicit local-dev escape hatch.
func TestRequireAtRestEncryptionConfig(t *testing.T) {
	env := map[string]string{
		"PROBECTL_AUTH_MODE":                  "session",
		"PROBECTL_REQUIRE_AT_REST_ENCRYPTION": "false",
		"PROBECTL_ALLOW_KEYLESS_DEV":          "true",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.RequireAtRestEncryption {
		t.Fatal("PROBECTL_REQUIRE_AT_REST_ENCRYPTION=false must clear the posture flag")
	}
	if !cfg.AllowKeylessDev {
		t.Fatal("PROBECTL_ALLOW_KEYLESS_DEV=true must enable the explicit dev escape hatch")
	}

	def, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("load default: %v", err)
	}
	if !def.RequireAtRestEncryption {
		t.Fatal("at-rest encryption must be required by default")
	}
	if def.AllowKeylessDev {
		t.Fatal("keyless dev mode must default off")
	}
}

// TENANT-102: the ClickHouse tenant-scoping knobs parse and default off.
func TestFlowCHScopingConfig(t *testing.T) {
	env := map[string]string{
		"PROBECTL_FLOWSTORE_TENANT_SCOPING": "true",
		"PROBECTL_FLOWSTORE_READER_USER":    "probectl_reader",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.FlowCHTenantScoping || cfg.FlowCHReaderUser != "probectl_reader" {
		t.Fatalf("scoping knobs not parsed: %+v / %q", cfg.FlowCHTenantScoping, cfg.FlowCHReaderUser)
	}
	def, _ := Load(func(string) string { return "" })
	if def.FlowCHTenantScoping {
		t.Fatal("CH tenant scoping must default off")
	}
}
