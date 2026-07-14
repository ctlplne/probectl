// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
		"PROBECTL_ENDPOINTSTORE_READER_USER",
	} {
		if env[key] == "" {
			t.Fatalf("values-multitenant.yaml must ship %s so ClickHouse tenant scoping cannot silently downgrade", key)
		}
	}
}

func TestStrictHelmValuesShipRegulatedDeploymentProfile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "probectl", "values-strict.yaml"))
	if err != nil {
		t.Fatalf("read values-strict.yaml: %v", err)
	}
	var values struct {
		Control struct {
			ExtraEnv map[string]string `yaml:"extraEnv"`
		} `yaml:"control"`
	}
	if err := yaml.Unmarshal(raw, &values); err != nil {
		t.Fatalf("parse values-strict.yaml: %v", err)
	}
	if got := values.Control.ExtraEnv["PROBECTL_DEPLOYMENT_PROFILE"]; got != "regulated" {
		t.Fatalf("values-strict.yaml must set PROBECTL_DEPLOYMENT_PROFILE=regulated, got %q", got)
	}
}
