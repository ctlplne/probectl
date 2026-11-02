// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

import (
	"net/netip"
	"regexp"
	"sort"
)

// Snapshot is an immutable, revision-pinned view of one tenant and routing
// context. The caller must load it through tenant-scoped storage and enforce
// its own query memory budget before using it. Reusing one snapshot for every
// distinct subject avoids recompiling rules for each flow row.
type Snapshot struct {
	scope       Scope
	revision    int64
	definitions map[string]Definition
	assignments map[string][]Assignment
	cidrRules   map[string][]compiledRule
	nameRules   map[string][]compiledRule
	snmpRules   map[string][]compiledRule
}

// Revision returns the committed tag revision captured with this snapshot.
// A zero-value snapshot has no authority to label a query result.
func (s *Snapshot) Revision() (int64, error) {
	if s == nil || !validScope(s.scope) || s.revision <= 0 {
		return 0, ErrScopeMismatch
	}
	return s.revision, nil
}

type compiledRule struct {
	rule    Rule
	pattern *regexp.Regexp
	bits    int
}

func subjectKey(kind, id string) string { return kind + "\x00" + id }
func cidrKey(kind, side, prefix string) string {
	return kind + "\x00" + side + "\x00" + prefix
}
func snmpKey(kind, field, value string) string {
	return kind + "\x00" + field + "\x00" + value
}

// NewSnapshot rejects a mixed-scope or malformed snapshot in its entirety.
// The returned maps and compiled expressions are private and never alias the
// caller's slices, so a later rule edit cannot change an existing query page.
func NewSnapshot(scope Scope, revision int64, definitions []Definition,
	assignments []Assignment, rules []Rule) (*Snapshot, error) {
	if !validScope(scope) || revision <= 0 {
		return nil, ErrScopeMismatch
	}
	if len(definitions) > maxDefinitions || len(assignments) > maxAssignments || len(rules) > maxRules {
		return nil, ErrInvalid
	}
	s := &Snapshot{scope: scope, revision: revision,
		definitions: make(map[string]Definition, len(definitions)),
		assignments: make(map[string][]Assignment),
		cidrRules:   make(map[string][]compiledRule),
		nameRules:   make(map[string][]compiledRule),
		snmpRules:   make(map[string][]compiledRule)}
	keys := make(map[string]bool, len(definitions))
	for _, def := range definitions {
		if def.TenantID != scope.TenantID {
			return nil, ErrScopeMismatch
		}
		if !validUUID(def.ID) || ValidateKey(def.Key) != nil {
			return nil, ErrInvalid
		}
		if _, exists := s.definitions[def.ID]; exists || keys[def.Key] {
			return nil, ErrConflict
		}
		s.definitions[def.ID], keys[def.Key] = def, true
	}
	seenAssignment := make(map[string]bool, len(assignments))
	for _, assignment := range assignments {
		if err := validateAssignment(scope, s.definitions, assignment); err != nil {
			return nil, err
		}
		target := subjectKey(assignment.TargetKind, assignment.TargetID)
		unique := target + "\x00" + assignment.TagID + "\x00" + assignment.Source
		if seenAssignment[unique] {
			return nil, ErrConflict
		}
		seenAssignment[unique] = true
		s.assignments[target] = append(s.assignments[target], assignment)
	}
	seenRule := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if !sameScope(scope, rule.Scope) {
			return nil, ErrScopeMismatch
		}
		if seenRule[rule.ID] || validateRuleShape(rule) != nil {
			return nil, ErrInvalid
		}
		seenRule[rule.ID] = true
		if _, exists := s.definitions[rule.TagID]; !exists {
			return nil, ErrInvalid
		}
		compiled, prefix, err := compileRule(rule)
		if err != nil {
			return nil, err
		}
		switch rule.Match {
		case "cidr":
			key := cidrKey(rule.TargetKind, rule.AddressSide, prefix.String())
			s.cidrRules[key] = append(s.cidrRules[key], compiled)
		case "name_pattern":
			s.nameRules[rule.TargetKind] = append(s.nameRules[rule.TargetKind], compiled)
		case "snmp_field":
			key := snmpKey(rule.TargetKind, rule.SNMPField, rule.SNMPValue)
			s.snmpRules[key] = append(s.snmpRules[key], compiled)
		}
	}
	return s, nil
}

// ValidateRule applies the resolver's exact bounded rule grammar before a
// tenant write. Storage FKs then prove that the tag and context are owned by
// the same authenticated tenant.
func ValidateRule(rule Rule) error {
	if err := validateRuleShape(rule); err != nil {
		return err
	}
	_, _, err := compileRule(rule)
	return err
}

func validateRuleShape(rule Rule) error {
	if !validScope(rule.Scope) {
		return ErrScopeMismatch
	}
	if !validUUID(rule.ID) || !validUUID(rule.TagID) || !validKind(rule.TargetKind) ||
		!validText(rule.Value, maxValueBytes) || rule.Priority < -1000 || rule.Priority > 1000 {
		return ErrInvalid
	}
	return nil
}

func compileRule(rule Rule) (compiledRule, netip.Prefix, error) {
	compiled := compiledRule{rule: rule}
	switch rule.Match {
	case "cidr":
		if !validSide(rule.AddressSide) || rule.NamePattern != "" ||
			rule.SNMPField != "" || rule.SNMPValue != "" {
			return compiledRule{}, netip.Prefix{}, ErrInvalid
		}
		prefix, err := netip.ParsePrefix(rule.CIDR)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Masked().String() != rule.CIDR {
			return compiledRule{}, netip.Prefix{}, ErrInvalid
		}
		compiled.bits = prefix.Bits()
		return compiled, prefix, nil
	case "name_pattern":
		if rule.AddressSide != "" || rule.CIDR != "" ||
			rule.SNMPField != "" || rule.SNMPValue != "" ||
			!validText(rule.NamePattern, maxPatternBytes) {
			return compiledRule{}, netip.Prefix{}, ErrInvalid
		}
		pattern, err := regexp.Compile(rule.NamePattern)
		if err != nil {
			return compiledRule{}, netip.Prefix{}, ErrInvalid
		}
		compiled.pattern = pattern
		return compiled, netip.Prefix{}, nil
	case "snmp_field":
		if rule.AddressSide != "" || rule.CIDR != "" || rule.NamePattern != "" ||
			!validText(rule.SNMPValue, 256) {
			return compiledRule{}, netip.Prefix{}, ErrInvalid
		}
		switch rule.SNMPField {
		case "sys_name", "sys_descr", "if_name", "if_descr":
			return compiled, netip.Prefix{}, nil
		default:
			return compiledRule{}, netip.Prefix{}, ErrInvalid
		}
	default:
		return compiledRule{}, netip.Prefix{}, ErrInvalid
	}
}

// Resolve uses the current snapshot's revision even when the subject facts
// came from retained historical telemetry. The same Snapshot must be kept for
// all pages, comparisons and exports of one query.
func (s *Snapshot) Resolve(subject Subject) ([]Resolved, error) {
	if s == nil || !validScope(s.scope) || s.revision <= 0 ||
		!sameScope(s.scope, subject.Scope) {
		return nil, ErrScopeMismatch
	}
	if !validKind(subject.Kind) || !validText(subject.ID, maxTargetIDBytes) ||
		(subject.Address.IsValid() && subject.Address.Zone() != "") ||
		(subject.AddressSide != "" && !validSide(subject.AddressSide)) {
		return nil, ErrInvalid
	}
	selected := make(map[string]candidate)
	for _, assignment := range s.assignments[subjectKey(subject.Kind, subject.ID)] {
		rank := 1
		if assignment.Source == "manual" {
			rank = 3
		}
		proposed := candidate{Resolved: Resolved{TagID: assignment.TagID,
			Key: s.definitions[assignment.TagID].Key, Value: assignment.Value,
			Source: assignment.Source, SourceID: assignment.SourceRef,
			Revision: s.revision}, rank: rank}
		if previous, exists := selected[assignment.TagID]; !exists || proposed.rank > previous.rank {
			selected[assignment.TagID] = proposed
		}
	}
	selectRule := func(compiled compiledRule) {
		rule := compiled.rule
		proposed := candidate{Resolved: Resolved{TagID: rule.TagID,
			Key: s.definitions[rule.TagID].Key, Value: rule.Value,
			Source: "rule", SourceID: rule.ID, Revision: s.revision},
			rank: 2, specificity: compiled.bits, priority: rule.Priority}
		if previous, exists := selected[rule.TagID]; !exists || betterRule(proposed, previous) {
			selected[rule.TagID] = proposed
		}
	}
	if subject.Name != "" {
		for _, compiled := range s.nameRules[subject.Kind] {
			if compiled.pattern.MatchString(subject.Name) {
				selectRule(compiled)
			}
		}
	}
	for _, field := range []string{"sys_name", "sys_descr", "if_name", "if_descr"} {
		if value := subject.SNMP[field]; value != "" {
			for _, compiled := range s.snmpRules[snmpKey(subject.Kind, field, value)] {
				selectRule(compiled)
			}
		}
	}
	if subject.Address.IsValid() && subject.AddressSide != "" {
		for bits := 0; bits <= subject.Address.BitLen(); bits++ {
			prefix := netip.PrefixFrom(subject.Address, bits).Masked()
			for _, compiled := range s.cidrRules[cidrKey(subject.Kind, subject.AddressSide, prefix.String())] {
				selectRule(compiled)
			}
		}
	}
	out := make([]Resolved, 0, len(selected))
	for _, selected := range selected {
		out = append(out, selected.Resolved)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
