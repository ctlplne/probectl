// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bufio"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var chartOwnedEnvRE = regexp.MustCompile(`(?m)^[[:space:]]*(PROBECTL_[A-Z0-9_]+):`)

func discoverChartOwnedControlEnv(t *testing.T) []string {
	t.Helper()
	owned := map[string]struct{}{}
	for _, path := range []string{
		"deploy/helm/probectl/templates/configmap.yaml",
		"deploy/helm/probectl/templates/secret.yaml",
	} {
		for _, match := range chartOwnedEnvRE.FindAllStringSubmatch(readArtifact(t, path), -1) {
			owned[match[1]] = struct{}{}
		}
	}
	out := make([]string, 0, len(owned))
	for name := range owned {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func renderHelmConfigMap(t *testing.T, extra ...string) ([]byte, error) {
	t.Helper()
	args := []string{
		"template", "probectl", "deploy/helm/probectl",
		"--show-only", "templates/configmap.yaml",
		"--set", "ingress.host=h.example.com",
		"--set", "ingress.tlsSecretName=probectl-tls",
		"--set", "ingress.backendTLS.trustSecret=probectl-backend-ca",
		"--set", "ingress.backendTLS.serverName=probectl-control.probectl.svc",
		"--set", "control.tls.existingSecret=probectl-control-tls",
		"--set", "image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000",
		"--set", "secrets.envelopeKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"--set-string", "secrets.sessionHMACKey=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--set", "database.url=postgres://probectl:render-test@db:5432/probectl?sslmode=require",
	}
	args = append(args, extra...)
	cmd := exec.Command("helm", args...)
	cmd.Dir = repoRoot(t)
	return cmd.CombinedOutput()
}

// TestHelmRejectsChartOwnedExtraEnv proves generic extension values cannot
// replace security settings whose authoritative source is the chart.
func TestHelmRejectsChartOwnedExtraEnv(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	for _, name := range discoverChartOwnedControlEnv(t) {
		t.Run(name, func(t *testing.T) {
			out, err := renderHelmConfigMap(t, "--set-string", "control.extraEnv."+name+"=planted-override")
			if err == nil {
				t.Fatalf("chart accepted reserved control.extraEnv key %s:\n%s", name, out)
			}
			if !strings.Contains(string(out), name) {
				t.Fatalf("reserved-key failure does not identify %s:\n%s", name, out)
			}
		})
	}
}

var renderedConfigMapEnvRE = regexp.MustCompile(`^  (PROBECTL_[A-Z0-9_]+):`)

func TestHelmConfigMapKeysAreUniqueWithOrdinaryExtraEnv(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm is not installed")
	}
	out, err := renderHelmConfigMap(t,
		"--set-string", "control.extraEnv.PROBECTL_BUS_MODE=memory",
		"--set-string", "control.extraEnv.PROBECTL_REGION=local",
	)
	if err != nil {
		t.Fatalf("ordinary control.extraEnv render failed: %v\n%s", err, out)
	}
	counts := map[string]int{}
	scan := bufio.NewScanner(strings.NewReader(string(out)))
	for scan.Scan() {
		if match := renderedConfigMapEnvRE.FindStringSubmatch(scan.Text()); len(match) == 2 {
			counts[match[1]]++
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	for name, count := range counts {
		if count != 1 {
			t.Errorf("rendered ConfigMap key %s appears %d times, want exactly once", name, count)
		}
	}
	for _, name := range []string{"PROBECTL_BUS_MODE", "PROBECTL_REGION"} {
		if counts[name] != 1 {
			t.Errorf("ordinary extension key %s count = %d, want 1", name, counts[name])
		}
	}
}
