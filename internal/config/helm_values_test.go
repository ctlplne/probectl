// SPDX-License-Identifier: LicenseRef-probectl-TBD

package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMultitenantHelmValuesShipClickHouseReaderUsers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "probectl", "values-multitenant.yaml"))
	if err != nil {
		t.Fatalf("read values-multitenant.yaml: %v", err)
	}
	var values struct {
		Control struct {
			ExtraEnv map[string]string `yaml:"extraEnv"`
		} `yaml:"control"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse values-multitenant.yaml: %v", err)
	}
	env := values.Control.ExtraEnv
	if env["PROBECTL_DEPLOYMENT_PROFILE"] != "multi-tenant" {
		t.Fatalf("values-multitenant.yaml must set PROBECTL_DEPLOYMENT_PROFILE=multi-tenant, got %q",
			env["PROBECTL_DEPLOYMENT_PROFILE"])
	}
	for _, key := range []string{
		"PROBECTL_PATHSTORE_READER_USER",
		"PROBECTL_FLOWSTORE_READER_USER",
		"PROBECTL_OTELSTORE_READER_USER",
		"PROBECTL_EBPFSTORE_READER_USER",
	} {
		if env[key] == "" {
			t.Fatalf("values-multitenant.yaml must ship %s so ClickHouse tenant scoping cannot silently downgrade", key)
		}
	}
}
