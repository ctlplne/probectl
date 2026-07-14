// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package compliance

// Segmentation policy (S46, F43): the operator DECLARES the intended
// segmentation — named zones (CIDR sets) and forbidden zone→zone intents,
// mapped to compliance frameworks (PCI DSS segmentation, NIST zero-trust) —
// and probectl validates it against OBSERVED traffic (eBPF + flow).
//
// The honesty contract (the S46 watch-out, non-negotiable): observed ≠
// intended. A pair with no observed traffic is NOT proven blocked — its
// verdict is "not_observed", never "compliant". probectl validates; it never
// enforces (out of scope by design, guardrail 9).

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Zone is a named address space ("cde", "corp", "dmz").
type Zone struct {
	Name  string   `yaml:"name" json:"name"`
	CIDRs []string `yaml:"cidrs" json:"cidrs"`

	prefixes []netip.Prefix
}

// Rule forbids traffic between two zones (optionally port-scoped). Rules are
// directional; declare both directions for a full isolation boundary (or use
// bidirectional: true).
type Rule struct {
	ID            string   `yaml:"id" json:"id"`
	Description   string   `yaml:"description,omitempty" json:"description,omitempty"`
	From          string   `yaml:"from" json:"from"`
	To            string   `yaml:"to" json:"to"`
	Bidirectional bool     `yaml:"bidirectional,omitempty" json:"bidirectional,omitempty"`
	Ports         []uint16 `yaml:"ports,omitempty" json:"ports,omitempty"` // empty = all ports
	// Frameworks maps the rule onto audit language, e.g.
	// "pci-dss": "Req 1.3.x — CDE segmentation", "nist-800-207": "...".
	Frameworks map[string]string `yaml:"frameworks,omitempty" json:"frameworks,omitempty"`
}

// Policy is one declared segmentation policy.
type Policy struct {
	Name  string `yaml:"name" json:"name"`
	Zones []Zone `yaml:"zones" json:"zones"`
	Rules []Rule `yaml:"rules" json:"rules"`
}

// ParsePolicy validates one YAML policy document (strict fields).
func ParsePolicy(raw []byte) (Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Policy{}, fmt.Errorf("compliance: parse policy: %w", err)
	}
	if p.Name == "" {
		return Policy{}, fmt.Errorf("compliance: policy name is required")
	}
	zones := map[string]bool{}
	for zi := range p.Zones {
		z := &p.Zones[zi]
		if z.Name == "" || len(z.CIDRs) == 0 {
			return Policy{}, fmt.Errorf("compliance: policy %s: every zone needs a name and cidrs", p.Name)
		}
		if zones[z.Name] {
			return Policy{}, fmt.Errorf("compliance: policy %s: duplicate zone %q", p.Name, z.Name)
		}
		zones[z.Name] = true
		for _, c := range z.CIDRs {
			pfx, err := netip.ParsePrefix(strings.TrimSpace(c))
			if err != nil {
				return Policy{}, fmt.Errorf("compliance: policy %s zone %s: %w", p.Name, z.Name, err)
			}
			z.prefixes = append(z.prefixes, pfx)
		}
	}
	ids := map[string]bool{}
	for _, r := range p.Rules {
		switch {
		case r.ID == "":
			return Policy{}, fmt.Errorf("compliance: policy %s: every rule needs an id", p.Name)
		case ids[r.ID]:
			return Policy{}, fmt.Errorf("compliance: policy %s: duplicate rule %q", p.Name, r.ID)
		case !zones[r.From] || !zones[r.To]:
			return Policy{}, fmt.Errorf("compliance: policy %s rule %s: from/to must name declared zones", p.Name, r.ID)
		case r.From == r.To:
			return Policy{}, fmt.Errorf("compliance: policy %s rule %s: from and to must differ", p.Name, r.ID)
		}
		ids[r.ID] = true
	}
	if len(p.Rules) == 0 {
		return Policy{}, fmt.Errorf("compliance: policy %s declares no rules", p.Name)
	}
	return p, nil
}

// LoadDir parses every *.yaml/*.yml policy in dir (multi-document allowed).
// dir "" loads nothing; a malformed file FAILS startup (an operator who
// believes a boundary is validated must be right).
func LoadDir(dir string) ([]Policy, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("compliance: policies dir: %w", err)
	}
	var out []Policy
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("compliance: read %s: %w", name, err)
		}
		for _, doc := range strings.Split(string(raw), "\n---") {
			if strings.TrimSpace(doc) == "" {
				continue
			}
			p, err := ParsePolicy([]byte(doc))
			if err != nil {
				return nil, fmt.Errorf("compliance: %s: %w", name, err)
			}
			if seen[p.Name] {
				return nil, fmt.Errorf("compliance: duplicate policy %q (file %s)", p.Name, name)
			}
			seen[p.Name] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// zoneOf resolves an address to the first containing zone (longest prefix).
func (p Policy) zoneOf(addr string) (string, bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return "", false
	}
	best := ""
	bestBits := -1
	for _, z := range p.Zones {
		for _, pfx := range z.prefixes {
			if pfx.Contains(ip) && pfx.Bits() > bestBits {
				best, bestBits = z.Name, pfx.Bits()
			}
		}
	}
	return best, bestBits >= 0
}

// portMatch reports whether the rule covers the destination port.
func (r Rule) portMatch(port uint16) bool {
	if len(r.Ports) == 0 {
		return true
	}
	for _, p := range r.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// pairKey canonicalizes a directional zone pair.
func pairKey(from, to string) string { return from + "→" + to }

// RulePairs lists the directional pairs a rule covers (1 or 2).
func (r Rule) RulePairs() []string {
	pairs := []string{pairKey(r.From, r.To)}
	if r.Bidirectional {
		pairs = append(pairs, pairKey(r.To, r.From))
	}
	return pairs
}

// describePorts renders the port scope for evidence text.
func (r Rule) describePorts() string {
	if len(r.Ports) == 0 {
		return "all ports"
	}
	parts := make([]string, len(r.Ports))
	for i, p := range r.Ports {
		parts[i] = strconv.Itoa(int(p))
	}
	sort.Strings(parts)
	return "ports " + strings.Join(parts, ",")
}
