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

import "time"

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
