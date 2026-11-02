// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package tags resolves current tenant-owned metadata against already
// authorized canonical subjects. It does not infer ownership from a name,
// address, source export or caller-provided tag: the storage/API layer must
// supply one FORCE-RLS tenant/context snapshot before calling Resolve.
package tags

import (
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalid       = errors.New("tags: invalid bounded definition or rule")
	ErrScopeMismatch = errors.New("tags: tenant or routing context mismatch")
	ErrConflict      = errors.New("tags: duplicate key, assignment or rule")
)

const (
	maxDefinitions  = 64
	maxRules        = 5000
	maxAssignments  = 10000
	maxValueBytes   = 128
	maxPatternBytes = 256
)

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var sourceRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var reservedKeys = map[string]bool{
	"tenant_id": true, "agent_id": true, "bytes": true, "packets": true,
	"flows": true, "src_addr": true, "dst_addr": true, "exporter": true,
	"in_if": true, "out_if": true,
}

type Scope struct {
	TenantID  string
	ContextID string
}

type Definition struct {
	TenantID string
	ID       string
	Key      string
}

// Subject contains only identity and facts already bound to Scope. SNMP
// fields must come from authenticated device inventory, not a source export.
type Subject struct {
	Scope
	Kind        string
	ID          string
	AddressSide string
	Address     netip.Addr
	Name        string
	SNMP        map[string]string
}

type Assignment struct {
	Scope
	TagID      string
	TargetKind string
	TargetID   string
	Value      string
	Source     string // manual or netbox
	SourceRef  string // provenance ID, never a credential or raw response
}

type Rule struct {
	Scope
	ID          string
	TagID       string
	TargetKind  string
	Match       string // cidr, name_pattern or snmp_field
	AddressSide string
	CIDR        string
	NamePattern string
	SNMPField   string
	SNMPValue   string
	Value       string
	Priority    int
}

type Resolved struct {
	TagID    string `json:"tag_id"`
	Key      string `json:"key"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	SourceID string `json:"source_id,omitempty"`
	Revision int64  `json:"revision"`
}

type candidate struct {
	Resolved
	rank        int
	specificity int
	priority    int
}

func validUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func validText(raw string, maxBytes int) bool {
	if raw == "" || len(raw) > maxBytes || strings.TrimSpace(raw) != raw {
		return false
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validKind(kind string) bool {
	switch kind {
	case "exporter", "interface", "prefix", "device", "agent", "test":
		return true
	default:
		return false
	}
}

func validSide(side string) bool {
	switch side {
	case "src", "dst", "exporter", "interface", "device":
		return true
	default:
		return false
	}
}

func validScope(scope Scope) bool {
	return validUUID(scope.TenantID) && validUUID(scope.ContextID)
}

func sameScope(a, b Scope) bool {
	return a.TenantID == b.TenantID && a.ContextID == b.ContextID
}

// resolve applies one immutable tenant/context rule revision to one canonical
// subject. Manual wins over a matching rule, which wins over an imported
// NetBox suggestion. Among CIDR rules the longest prefix wins, then explicit
// priority and immutable rule ID; other rule types use priority then ID.
// Mixed-tenant snapshots fail closed rather than silently dropping rows.
func resolve(scope Scope, revision int64, subject Subject, definitions []Definition,
	assignments []Assignment, rules []Rule) ([]Resolved, error) {
	if !validScope(scope) || revision <= 0 || !sameScope(scope, subject.Scope) {
		return nil, ErrScopeMismatch
	}
	if !validKind(subject.Kind) || !validText(subject.ID, 256) ||
		len(definitions) > maxDefinitions || len(assignments) > maxAssignments || len(rules) > maxRules ||
		(subject.Address.IsValid() && subject.Address.Zone() != "") ||
		(subject.AddressSide != "" && !validSide(subject.AddressSide)) {
		return nil, ErrInvalid
	}
	defs := make(map[string]Definition, len(definitions))
	keys := make(map[string]bool, len(definitions))
	for _, def := range definitions {
		if def.TenantID != scope.TenantID {
			return nil, ErrScopeMismatch
		}
		if !validUUID(def.ID) || !keyPattern.MatchString(def.Key) ||
			reservedKeys[def.Key] ||
			strings.HasPrefix(def.Key, "probectl_") {
			return nil, ErrInvalid
		}
		if _, exists := defs[def.ID]; exists || keys[def.Key] {
			return nil, ErrConflict
		}
		defs[def.ID], keys[def.Key] = def, true
	}
	selected := make(map[string]candidate, len(defs))
	seenAssignment := make(map[string]bool, len(assignments))
	for _, assignment := range assignments {
		if err := validateAssignment(scope, defs, assignment); err != nil {
			return nil, err
		}
		if assignment.TargetKind != subject.Kind || assignment.TargetID != subject.ID {
			continue
		}
		key := assignment.TagID + "\x00" + assignment.Source
		if seenAssignment[key] {
			return nil, ErrConflict
		}
		seenAssignment[key] = true
		rank := 1
		if assignment.Source == "manual" {
			rank = 3
		}
		proposed := candidate{Resolved: Resolved{TagID: assignment.TagID,
			Key: defs[assignment.TagID].Key, Value: assignment.Value,
			Source: assignment.Source, SourceID: assignment.SourceRef,
			Revision: revision}, rank: rank}
		if previous, exists := selected[assignment.TagID]; !exists || proposed.rank > previous.rank {
			selected[assignment.TagID] = proposed
		}
	}
	seenRule := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if !sameScope(scope, rule.Scope) {
			return nil, ErrScopeMismatch
		}
		if !validUUID(rule.ID) || seenRule[rule.ID] ||
			!validKind(rule.TargetKind) || !validText(rule.Value, maxValueBytes) ||
			rule.Priority < -1000 || rule.Priority > 1000 {
			return nil, ErrInvalid
		}
		seenRule[rule.ID] = true
		if _, exists := defs[rule.TagID]; !exists {
			return nil, ErrInvalid
		}
		match, specificity, err := ruleMatches(rule, subject)
		if err != nil {
			return nil, err
		}
		if !match || rule.TargetKind != subject.Kind {
			continue
		}
		proposed := candidate{Resolved: Resolved{TagID: rule.TagID,
			Key: defs[rule.TagID].Key, Value: rule.Value,
			Source: "rule", SourceID: rule.ID, Revision: revision},
			rank: 2, specificity: specificity, priority: rule.Priority}
		if previous, exists := selected[rule.TagID]; !exists || betterRule(proposed, previous) {
			selected[rule.TagID] = proposed
		}
	}
	out := make([]Resolved, 0, len(selected))
	for _, selected := range selected {
		out = append(out, selected.Resolved)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func validateAssignment(scope Scope, defs map[string]Definition, assignment Assignment) error {
	if !sameScope(scope, assignment.Scope) {
		return ErrScopeMismatch
	}
	if _, exists := defs[assignment.TagID]; !exists ||
		!validKind(assignment.TargetKind) || !validText(assignment.TargetID, 256) ||
		!validText(assignment.Value, maxValueBytes) ||
		(assignment.Source != "manual" && assignment.Source != "netbox") ||
		(assignment.Source == "manual" && assignment.SourceRef != "") ||
		(assignment.Source == "netbox" && !sourceRefPattern.MatchString(assignment.SourceRef)) {
		return ErrInvalid
	}
	return nil
}

func betterRule(next, current candidate) bool {
	if next.rank != current.rank {
		return next.rank > current.rank
	}
	if next.rank != 2 {
		return false
	}
	if next.specificity != current.specificity {
		return next.specificity > current.specificity
	}
	if next.priority != current.priority {
		return next.priority > current.priority
	}
	return next.SourceID < current.SourceID
}

func ruleMatches(rule Rule, subject Subject) (bool, int, error) {
	switch rule.Match {
	case "cidr":
		if !validSide(rule.AddressSide) || rule.NamePattern != "" ||
			rule.SNMPField != "" || rule.SNMPValue != "" {
			return false, 0, ErrInvalid
		}
		prefix, err := netip.ParsePrefix(rule.CIDR)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Masked().String() != rule.CIDR {
			return false, 0, ErrInvalid
		}
		return subject.AddressSide == rule.AddressSide && subject.Address.IsValid() &&
			prefix.Contains(subject.Address), prefix.Bits(), nil
	case "name_pattern":
		if rule.AddressSide != "" || rule.CIDR != "" ||
			rule.SNMPField != "" || rule.SNMPValue != "" ||
			!validText(rule.NamePattern, maxPatternBytes) {
			return false, 0, ErrInvalid
		}
		pattern, err := regexp.Compile(rule.NamePattern)
		if err != nil {
			return false, 0, ErrInvalid
		}
		return subject.Name != "" && pattern.MatchString(subject.Name), 0, nil
	case "snmp_field":
		if rule.AddressSide != "" || rule.CIDR != "" || rule.NamePattern != "" ||
			!validText(rule.SNMPValue, 256) {
			return false, 0, ErrInvalid
		}
		switch rule.SNMPField {
		case "sys_name", "sys_descr", "if_name", "if_descr":
		default:
			return false, 0, ErrInvalid
		}
		return subject.SNMP[rule.SNMPField] == rule.SNMPValue, 0, nil
	default:
		return false, 0, ErrInvalid
	}
}
