// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package threat

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"
)

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

func TestLoadRulesDefaults(t *testing.T) {
	rules, err := LoadRules("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 6 {
		t.Fatalf("built-in ruleset has %d rules, want 6", len(rules))
	}
	kinds := map[RuleKind]bool{}
	for _, r := range rules {
		kinds[r.Kind] = true
		if !r.On() {
			t.Errorf("default rule %s is disabled", r.ID)
		}
		if r.Suppress <= 0 {
			t.Errorf("default rule %s has no suppression window", r.ID)
		}
		if r.Version < 1 || r.Severity == "" || r.BaseConfidence <= 0 {
			t.Errorf("default rule %s incomplete: %+v", r.ID, r)
		}
	}
	for _, k := range []RuleKind{KindDNSDGA, KindDNSExfil, KindBeaconing, KindEgressVolume, KindEgressIntel, KindLateral} {
		if !kinds[k] {
			t.Errorf("missing default rule for kind %s", k)
		}
	}
}

func TestLoadRulesOverrideTunesThreshold(t *testing.T) {
	dir := t.TempDir()
	// The operator drops the beaconing min_samples to 4 and bumps suppression.
	err := writeFile(dir+"/tune.yml", `rules:
  - id: ndr-beaconing-default
    version: 2
    kind: beaconing
    name: Periodic beaconing (tuned)
    severity: warning
    base_confidence: 45
    suppress: 4h
    thresholds: { min_samples: 4, max_jitter: 0.2, min_interval_s: 5, max_interval_s: 3600 }
  - id: ndr-custom-lateral
    version: 1
    kind: lateral
    name: Custom lateral watch
    severity: info
    base_confidence: 30
    suppress: 10m
    thresholds: { fanout: 3, window_s: 60 }
`)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 7 { // 6 defaults, 1 replaced + 1 new
		t.Fatalf("rules = %d, want 7", len(rules))
	}
	var beacon *DetectionRule
	for i := range rules {
		if rules[i].ID == "ndr-beaconing-default" {
			beacon = &rules[i]
		}
	}
	if beacon == nil || beacon.Version != 2 || beacon.Threshold("min_samples", 0) != 4 ||
		beacon.Suppress != 4*time.Hour {
		t.Fatalf("override not applied: %+v", beacon)
	}
}

func TestLoadRulesFailsClosed(t *testing.T) {
	cases := map[string]string{
		"unknown kind": `rules: [{id: x, version: 1, kind: nonsense, name: n, severity: info, base_confidence: 10, suppress: 1m}]`,
		"bad severity": `rules: [{id: x, version: 1, kind: lateral, name: n, severity: loud, base_confidence: 10, suppress: 1m}]`,
		"zero version": `rules: [{id: x, version: 0, kind: lateral, name: n, severity: info, base_confidence: 10, suppress: 1m}]`,
		"dup id":       `rules: [{id: ndr-lateral-default, version: 1, kind: lateral, name: n, severity: info, base_confidence: 10, suppress: 1m}, {id: ndr-lateral-default, version: 1, kind: lateral, name: n, severity: info, base_confidence: 10, suppress: 1m}]`,
		"not yaml":     `{{{{`,
	}
	for name, content := range cases {
		dir := t.TempDir()
		if err := writeFile(dir+"/r.yaml", content); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRules(dir); err == nil {
			t.Errorf("%s: malformed ruleset loaded without error", name)
		}
	}
	// A missing override dir is also an explicit error (fail closed, not
	// silently running on defaults the operator thinks they replaced).
	if _, err := LoadRules("/does/not/exist"); err == nil || !strings.Contains(err.Error(), "rules dir") {
		t.Errorf("missing rules dir: %v", err)
	}
}

func TestLoadRulesBoundsOverlayFile(t *testing.T) {
	const limit = 1 << 20
	valid := []byte(`rules:
  - id: ndr-size-bound-test
    version: 1
    kind: lateral
    name: Size bound test
    severity: info
    base_confidence: 10
    suppress: 1m
    thresholds: { fanout: 3, window_s: 60 }
`)
	pad := func(size int) []byte {
		t.Helper()
		if size < len(valid)+2 {
			t.Fatalf("fixture size %d is too small", size)
		}
		return append(append(append([]byte{}, valid...), '\n', '#'), bytes.Repeat([]byte{'x'}, size-len(valid)-2)...)
	}

	t.Run("maximum", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/maximum.yaml", pad(limit), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRules(dir); err != nil {
			t.Fatalf("maximum-sized rule file rejected: %v", err)
		}
	})

	t.Run("one past maximum", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(dir+"/oversized.yaml", pad(limit+1), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRules(dir); err == nil || !strings.Contains(err.Error(), "exceeds 1048576-byte limit") {
			t.Fatalf("one-past-maximum rule file error = %v", err)
		}
	})
}
