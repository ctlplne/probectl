// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package incident is probectl's cross-plane incident + correlation foundation
// (S17): related signals from any plane (network, BGP, and — without schema churn
// — future threat/change/cost/SLO planes) group into a single Incident with a
// coherent, time-ordered timeline.
//
// Extensibility is the design constraint (S17 watch-out): a Signal is a generic
// envelope with a free-form Attributes map, so a new plane contributes signals by
// mapping its native event onto a Signal — no change to this package or the
// schema. Incidents are tenant-owned (RLS at the store, F50); correlation only
// ever groups a tenant's own signals.
package incident

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// MaxSignalsPerRead bounds one incident-room response. SignalCount remains the
// full durable count; callers can distinguish a truncated evidence window from
// a complete read instead of mistaking omitted planes for healthy zeroes.
const MaxSignalsPerRead = 500

// Severity is an incident/signal triage level, ordered info < warning < critical.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Max returns the higher-severity of two levels.
func Max(a, b Severity) Severity {
	if b.rank() > a.rank() {
		return b
	}
	if a.rank() == 0 {
		return SeverityInfo
	}
	return a
}

// SeverityRank exposes a severity's numeric rank (for storage / ordering).
func SeverityRank(s Severity) int { return s.rank() }

// Status is an incident's lifecycle state.
type Status string

const (
	StatusOpen     Status = "open"
	StatusResolved Status = "resolved"
)

// Signal is one plane's observation fed into correlation. Plane and Kind are
// free-form strings so new planes need no code change here; Target and Prefix are
// the correlation keys (a host/IP/URL and/or a CIDR); Attributes carries arbitrary
// plane-specific context.
type Signal struct {
	ID         string            `json:"id,omitempty"`
	TenantID   string            `json:"tenant_id"`
	Plane      string            `json:"plane"` // "network" | "bgp" | "threat" | "change" | ...
	Kind       string            `json:"kind"`  // e.g. "alert.firing", "bgp.possible_hijack"
	Severity   Severity          `json:"severity"`
	Title      string            `json:"title"`
	Summary    string            `json:"summary,omitempty"`
	Target     string            `json:"target,omitempty"`
	Prefix     string            `json:"prefix,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// Fingerprint identifies THIS event: the same tenant, plane, kind, target,
// prefix, occurrence time, text and attributes always hash the same, so a
// re-delivered or re-published signal is recognized as the one already on the
// timeline (DPR-078). The bus is at-least-once and analyzers re-run, so
// duplicates are a normal condition, not a fault; the lab's first BGP incident
// held 20,389 signals of which 18,020 were byte-identical copies.
func (s Signal) Fingerprint() string {
	keys := make([]string, 0, len(s.Attributes))
	for k := range s.Attributes {
		if strings.HasPrefix(k, "correlation.") {
			continue // derived by the correlator, not part of the event
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, part := range []string{s.TenantID, s.Plane, s.Kind, s.Target, s.Prefix,
		strconv.FormatInt(s.OccurredAt.UTC().UnixNano(), 10), s.Title, s.Summary} {
		b.WriteString(part)
		b.WriteByte(0)
	}
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(s.Attributes[k])
		b.WriteByte(0)
	}
	return hex.EncodeToString(crypto.Default.Hash([]byte(b.String())))
}

// CorrelationOverride is a tenant operator's durable instruction that a
// specific signal shape must no longer be grouped into SourceIncidentID. The
// original signal remains in the source timeline; DetachedIncidentID is the
// independently visible incident created from it. Active remains true until an
// explicit reversal.
type CorrelationOverride struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	SourceIncidentID   string     `json:"source_incident_id"`
	DetachedIncidentID string     `json:"detached_incident_id"`
	SourceSignalID     string     `json:"source_signal_id"`
	Plane              string     `json:"plane"`
	Kind               string     `json:"kind"`
	Target             string     `json:"target,omitempty"`
	Prefix             string     `json:"prefix,omitempty"`
	Reason             string     `json:"reason"`
	Active             bool       `json:"active"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	ReversedBy         string     `json:"reversed_by,omitempty"`
	ReversalReason     string     `json:"reversal_reason,omitempty"`
	ReversedAt         *time.Time `json:"reversed_at,omitempty"`
}

func (o CorrelationOverride) Matches(sig Signal) bool {
	return o.Active && o.TenantID == sig.TenantID && o.Plane == sig.Plane && o.Kind == sig.Kind &&
		o.Target == sig.Target && o.Prefix == sig.Prefix
}

// ErrNoCorrelationKey is returned when a signal carries neither Target nor
// Prefix. It is a distinct sentinel so a plane's ingest path can tell a
// programming error (no key) from a transient store failure.
var ErrNoCorrelationKey = errors.New("incident: signal has no correlation key (Target or Prefix)")

// CorrelationKey returns the value relatedness joins on, or "" when the signal
// carries none. A plane building signals can assert on this before emitting.
func (s Signal) CorrelationKey() string {
	if s.Target != "" {
		return s.Target
	}
	return s.Prefix
}

// validateCorrelationKey enforces the join contract at the ingest boundary.
func (s Signal) validateCorrelationKey() error {
	if s.CorrelationKey() != "" {
		return nil
	}
	return fmt.Errorf("%w: plane %q kind %q cannot correlate and would open one incident per signal",
		ErrNoCorrelationKey, s.Plane, s.Kind)
}

// Incident groups related signals. Signals is its timeline (populated on read).
type Incident struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Status      Status     `json:"status"`
	Severity    Severity   `json:"severity"`
	Title       string     `json:"title"`
	Target      string     `json:"target,omitempty"`
	Prefix      string     `json:"prefix,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	LastSeenAt  time.Time  `json:"last_seen_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
	SignalCount int        `json:"signal_count"`
	Signals     []Signal   `json:"signals,omitempty"`
	// SignalsTruncated is explicit coverage metadata for bounded incident-room
	// reads. SignalsLimit states the server cap when truncation occurred.
	SignalsTruncated bool `json:"signals_truncated"`
	SignalsLimit     int  `json:"signals_limit,omitempty"`
	// CorrelationOverrides makes operator intent visible in the incident room;
	// reversed rows remain history rather than disappearing.
	CorrelationOverrides []CorrelationOverride `json:"correlation_overrides,omitempty"`
}

// newIncident seeds an incident from the signal that opened it.
func newIncident(sig Signal) *Incident {
	target := sig.Target
	if target == "" {
		target = sig.Prefix
	}
	return &Incident{
		TenantID:    sig.TenantID,
		Status:      StatusOpen,
		Severity:    sig.Severity,
		Title:       sig.Title,
		Target:      target,
		Prefix:      sig.Prefix,
		StartedAt:   sig.OccurredAt,
		LastSeenAt:  sig.OccurredAt,
		SignalCount: 0, // incremented as signals are appended
	}
}
