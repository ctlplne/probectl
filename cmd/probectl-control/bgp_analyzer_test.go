// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBGPAnalyzerRuntimeBuildsTenantBoundReplay(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "analyzer.json")
	if err := os.WriteFile(configFile, []byte(`{"tenant_id":"tenant-a","monitored_prefixes":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PROBECTL_BGP_ANALYZER_CONFIG":      configFile,
		"PROBECTL_BGP_ANALYZER_SOURCE":      "replay",
		"PROBECTL_BGP_ANALYZER_SOURCE_FILE": "/fixtures/ris.jsonl",
		"PROBECTL_BUS_MODE":                 "kafka",
		"PROBECTL_BUS_BROKERS":              "kafka-0:9093, kafka-1:9093",
		"PROBECTL_BUS_TLS_ENABLED":          "true",
		"PROBECTL_BUS_SASL_PASSWORD":        "do-not-pass-to-python",
		"PATH":                              "/usr/bin",
	}
	rt, err := loadBGPAnalyzerRuntime(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if rt.process.TenantID != "tenant-a" || rt.process.Restart {
		t.Fatalf("process = %+v, want tenant-a finite replay", rt.process)
	}
	if got := strings.Join(rt.process.Args, " "); !strings.Contains(got, "--replay /fixtures/ris.jsonl") {
		t.Fatalf("args = %q", got)
	}
	if strings.Contains(strings.Join(rt.process.Env, "\n"), "do-not-pass-to-python") {
		t.Fatal("Kafka secret leaked into Python subprocess environment")
	}
	if len(rt.brokers) != 2 || !rt.security.TLSEnabled {
		t.Fatalf("bus runtime = brokers %v security %+v", rt.brokers, rt.security)
	}
}

func TestLoadBGPAnalyzerRuntimeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "analyzer.json")
	if err := os.WriteFile(configFile, []byte(`{"tenant_id":"tenant-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "missing config", env: map[string]string{}, want: "CONFIG is required"},
		{name: "missing source", env: map[string]string{"PROBECTL_BGP_ANALYZER_CONFIG": configFile}, want: "SOURCE is required"},
		{name: "separate memory bus", env: map[string]string{"PROBECTL_BGP_ANALYZER_CONFIG": configFile, "PROBECTL_BGP_ANALYZER_SOURCE": "ris-live", "PROBECTL_BUS_MODE": "memory"}, want: "must be kafka"},
		{name: "finite source needs file", env: map[string]string{"PROBECTL_BGP_ANALYZER_CONFIG": configFile, "PROBECTL_BGP_ANALYZER_SOURCE": "mrt", "PROBECTL_BUS_MODE": "kafka"}, want: "SOURCE_FILE is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadBGPAnalyzerRuntime(func(k string) string { return tc.env[k] })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}
