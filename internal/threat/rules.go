// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package threat

// Detection-as-code (S42, F37): behavioral detections are declared as
// Sigma-style, versioned YAML rules, not hardcoded constants. A built-in
// ruleset ships embedded (the engine works out of the box); operators tune,
// disable, or replace rules by dropping YAML files in a rules directory —
// thresholds, confidence, severity, and suppression are all rule fields
// because FALSE-POSITIVE MANAGEMENT IS THE PRODUCT (the S42 watch-out).
// Rules only ever produce signals; there is no action/block field by design
// (CLAUDE.md §7 guardrail 9).

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const maxRuleFileBytes = 1 << 20

// RuleKind names a behavioral detector the engine implements.
type RuleKind string

// The built-in detectors (S42's named detections).
const (
	KindDNSDGA       RuleKind = "dns_dga"       // algorithmically-generated domain lookups
	KindDNSExfil     RuleKind = "dns_exfil"     // data exfiltration over DNS qnames
	KindBeaconing    RuleKind = "beaconing"     // periodic C2-style callbacks
	KindEgressVolume RuleKind = "egress_volume" // egress byte-volume anomaly vs baseline
	KindEgressIntel  RuleKind = "egress_intel"  // egress to Tor exits / bad ASNs / IOC hosts
	KindLateral      RuleKind = "lateral"       // internal east-west fan-out
)

func knownKind(k RuleKind) bool {
	switch k {
	case KindDNSDGA, KindDNSExfil, KindBeaconing, KindEgressVolume, KindEgressIntel, KindLateral:
		return true
	}
	return false
}

// DetectionRule is one versioned detection-as-code rule.
type DetectionRule struct {
	ID          string   `yaml:"id"`      // stable identity, e.g. "ndr-beaconing-default"
	Version     int      `yaml:"version"` // bump on any behavioral change
	Kind        RuleKind `yaml:"kind"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`

	// Severity of the raised signal: info | warning | critical.
	Severity string `yaml:"severity"`
	// BaseConfidence (0..100) anchors scoring; detectors add evidence on top
	// and the result is clamped to 100.
	BaseConfidence int `yaml:"base_confidence"`
	// Suppress is the per-(rule, tenant, entity) re-fire window: once raised,
	// the same entity stays quiet until the window passes (alert fatigue).
	Suppress time.Duration `yaml:"suppress"`
	// Enabled defaults to true; operators disable a rule by overriding it
	// with enabled: false (tuning without code).
	Enabled *bool `yaml:"enabled,omitempty"`

	// Thresholds are the numeric tunables, detector-specific (documented in
	// the embedded ruleset); Lists are the string-list tunables (ports, ASNs).
	Thresholds map[string]float64  `yaml:"thresholds,omitempty"`
	Lists      map[string][]string `yaml:"lists,omitempty"`
}

// On reports whether the rule is enabled (default true).
func (r DetectionRule) On() bool { return r.Enabled == nil || *r.Enabled }

// Threshold returns a tunable or its default.
func (r DetectionRule) Threshold(key string, def float64) float64 {
	if v, ok := r.Thresholds[key]; ok {
		return v
	}
	return def
}

// ruleFile is the YAML document shape: a versioned list of rules.
type ruleFile struct {
	Rules []DetectionRule `yaml:"rules"`
}

//go:embed rules/*.yaml
var builtinRules embed.FS

// LoadRules returns the effective ruleset: the embedded defaults, overlaid
// with any *.yaml/*.yml files in dir (override matches by rule ID and
// REPLACES the default — including enabled: false to switch one off; new IDs
// add detections). dir "" means defaults only. Validation fails closed: a
// malformed rules directory is a startup error, not a silently-empty engine.
func LoadRules(dir string) ([]DetectionRule, error) {
	rules, err := loadFS()
	if err != nil {
		return nil, err // embedded defaults must parse (build-time invariant)
	}
	byID := make(map[string]int, len(rules))
	for i, r := range rules {
		byID[r.ID] = i
	}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("threat: rules dir: %w", err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
				continue
			}
			raw, err := readRuleFile(filepath.Join(dir, name))
			if err != nil {
				return nil, fmt.Errorf("threat: read rule file %s: %w", name, err)
			}
			var f ruleFile
			if err := yaml.Unmarshal(raw, &f); err != nil {
				return nil, fmt.Errorf("threat: parse rule file %s: %w", name, err)
			}
			inFile := map[string]bool{}
			for _, r := range f.Rules {
				if inFile[r.ID] {
					// Two rules with one ID in one file is an operator mistake,
					// not an override — fail closed rather than guess.
					return nil, fmt.Errorf("threat: rule file %s: duplicate rule id %q", name, r.ID)
				}
				inFile[r.ID] = true
				if i, ok := byID[r.ID]; ok {
					rules[i] = r // operator override replaces the default
				} else {
					byID[r.ID] = len(rules)
					rules = append(rules, r)
				}
			}
		}
	}
	if err := validateRules(rules); err != nil {
		return nil, err
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

func readRuleFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxRuleFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > maxRuleFileBytes {
		return nil, fmt.Errorf("rule file exceeds %d-byte limit", maxRuleFileBytes)
	}
	return raw, nil
}

func loadFS() ([]DetectionRule, error) {
	entries, err := builtinRules.ReadDir("rules")
	if err != nil {
		return nil, fmt.Errorf("threat: embedded rules: %w", err)
	}
	var rules []DetectionRule
	for _, e := range entries {
		raw, err := builtinRules.ReadFile("rules/" + e.Name())
		if err != nil {
			return nil, err
		}
		var f ruleFile
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("threat: embedded rule file %s: %w", e.Name(), err)
		}
		rules = append(rules, f.Rules...)
	}
	return rules, nil
}

func validateRules(rules []DetectionRule) error {
	seen := map[string]bool{}
	for _, r := range rules {
		switch {
		case r.ID == "":
			return fmt.Errorf("threat: rule with empty id")
		case seen[r.ID]:
			return fmt.Errorf("threat: duplicate rule id %q", r.ID)
		case r.Version < 1:
			return fmt.Errorf("threat: rule %s: version must be >= 1", r.ID)
		case !knownKind(r.Kind):
			return fmt.Errorf("threat: rule %s: unknown kind %q", r.ID, r.Kind)
		case r.Severity != "info" && r.Severity != "warning" && r.Severity != "critical":
			return fmt.Errorf("threat: rule %s: severity must be info|warning|critical", r.ID)
		case r.BaseConfidence < 0 || r.BaseConfidence > 100:
			return fmt.Errorf("threat: rule %s: base_confidence must be 0..100", r.ID)
		case r.Suppress < 0:
			return fmt.Errorf("threat: rule %s: suppress must be >= 0", r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}
