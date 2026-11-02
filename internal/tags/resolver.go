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
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	ErrInvalid       = errors.New("tags: invalid bounded definition or rule")
	ErrScopeMismatch = errors.New("tags: tenant or routing context mismatch")
	ErrConflict      = errors.New("tags: duplicate key, assignment or rule")
)

const (
	// MaxDefinitions bounds one tenant's tag vocabulary.
	MaxDefinitions = 64
	// MaxRules meets the published 25,000-populator incumbent tier.
	MaxRules = 25000
	// MaxAssignments admits the same number of reviewed bindings.
	MaxAssignments   = 25000
	maxDefinitions   = MaxDefinitions
	maxRules         = MaxRules
	maxAssignments   = MaxAssignments
	maxValueBytes    = 128
	maxPatternBytes  = 256
	maxTargetIDBytes = 2048
)

var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
var sourceRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// ValidateKey applies the same tenant vocabulary rule to write requests and
// immutable query snapshots. A stored tag can never shadow a native field.
func ValidateKey(key string) error {
	if !keyPattern.MatchString(key) || reservedKeys[key] || strings.HasPrefix(key, "probectl_") {
		return ErrInvalid
	}
	return nil
}

var reservedKeys = map[string]bool{
	"tenant_id": true, "agent_id": true, "bytes": true, "packets": true,
	"flows": true, "src_addr": true, "dst_addr": true, "exporter": true,
	"in_if": true, "out_if": true,
	// The native FX-1 registry and metric vocabulary cannot be shadowed by
	// tenant metadata. New native fields must be added here in the same change.
	"obs_domain": true, "protocol": true, "ts": true, "start_ts": true,
	"src_port": true, "dst_port": true, "transport": true, "net_type": true,
	"vlan": true, "tos": true, "tcp_flags": true, "next_hop": true,
	"raw_bytes": true, "raw_packets": true, "sampling": true,
	"bytes_scaled": true, "packets_scaled": true,
	"src_asn": true, "src_as_name": true, "src_country": true,
	"dst_asn": true, "dst_as_name": true, "dst_country": true,
	"row_id": true, "src_prefix": true, "dst_prefix": true,
	"dscp": true, "tcp_flag_names": true, "in_if_name": true,
	"out_if_name": true,
}

type Scope struct {
	TenantID  string
	ContextID string
}

type Definition struct {
	TenantID string `json:"tenant_id"`
	ID       string `json:"id"`
	Key      string `json:"key"`
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

// ExporterTargetID combines the authenticated agent and its operator-owned
// source reference without an ambiguous delimiter. Both sides must use this
// same encoding; neither a packet address nor an untrusted name is a target.
func ExporterTargetID(agentID, sourceRef string) (string, error) {
	if agentID == "" || sourceRef == "" || len(agentID) > 128 || len(sourceRef) > 1024 {
		return "", ErrInvalid
	}
	return base64.RawURLEncoding.EncodeToString([]byte(agentID)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(sourceRef)), nil
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

// resolve is the focused-call form used by rule tests. Production query paths
// reuse one Snapshot across all distinct subjects and pages.
func resolve(scope Scope, revision int64, subject Subject, definitions []Definition,
	assignments []Assignment, rules []Rule) ([]Resolved, error) {
	snapshot, err := NewSnapshot(scope, revision, definitions, assignments, rules)
	if err != nil {
		return nil, err
	}
	return snapshot.Resolve(subject)
}

func validateAssignment(scope Scope, defs map[string]Definition, assignment Assignment) error {
	if !sameScope(scope, assignment.Scope) {
		return ErrScopeMismatch
	}
	if _, exists := defs[assignment.TagID]; !exists ||
		!validKind(assignment.TargetKind) || !validText(assignment.TargetID, maxTargetIDBytes) ||
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
