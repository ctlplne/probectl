// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package alert is probectl's alerting engine (S16): threshold and baseline
// (anomaly) rules evaluated over the time-series produced by the result pipeline,
// with notification channels (webhook + email) and storm-avoiding debounce/dedupe.
//
// Tenancy: a Rule is tenant-owned (RLS-scoped at the store, F50); the engine only
// ever evaluates a tenant's rules against that tenant's series. Detection is a
// signal — probectl notifies, it does not act on the network.
package alert

import (
	"fmt"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/promapi"
)

// RuleType selects the evaluation strategy.
type RuleType string

const (
	// Threshold fires when an aggregated value crosses a fixed bound.
	Threshold RuleType = "threshold"
	// Baseline fires when a value deviates from its recent statistical baseline
	// (anomaly detection); it needs history and warms up on cold start.
	Baseline RuleType = "baseline"
	// Trap fires when the tenant's device agents deliver a matching
	// authenticated SNMP trap, and resolves on a matching clear trap or when
	// the hold time passes with no new match (D-61). It reads the tenant's
	// stored traps, not a metric series.
	Trap RuleType = "trap"
)

// Comparison is a threshold operator.
type Comparison string

const (
	GT  Comparison = "gt"
	LT  Comparison = "lt"
	GTE Comparison = "gte"
	LTE Comparison = "lte"
	EQ  Comparison = "eq"
	NEQ Comparison = "neq"
)

// Severity is an alert's triage level.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// ChannelSpec configures one notification destination on a rule. The webhook
// Secret (HMAC key) is sensitive and is redacted from API responses.
type ChannelSpec struct {
	Type       string   `json:"type"` // "webhook" | "email"
	URL        string   `json:"url,omitempty"`
	Secret     string   `json:"secret,omitempty"`
	Recipients []string `json:"recipients,omitempty"`
}

// TrapMetric is the series name a trap rule carries in its metric field and
// in every alert it raises: trap rules watch stored traps, not a TSDB series,
// and no TSDB series is ever written under this name.
const TrapMetric = "probectl_device_trap"

// Trap-rule hold bounds: how long a matching trap keeps the rule firing when
// no clear trap arrives.
const (
	DefaultTrapHoldSeconds = 900
	MinTrapHoldSeconds     = 60
	MaxTrapHoldSeconds     = 7 * 24 * 3600
	maxTrapOIDLength       = 255
	maxTrapDeviceLength    = 255
	maxTrapVarBindValue    = 512
)

// TrapMatch is what a trap rule matches. TrapOID is required; Device narrows
// the rule to one device address; VarBindOID + VarBindValue require one
// varbind of the trap to carry exactly that value (for example ifIndex.3 = 3
// to watch one interface). ClearTrapOID, when set, names the trap that
// resolves the alert (linkUp for linkDown); the clear trap must match the same
// device and varbind. HoldSeconds is how long a match keeps firing without a
// newer match or a clear trap.
type TrapMatch struct {
	TrapOID      string `json:"trap_oid"`
	ClearTrapOID string `json:"clear_trap_oid,omitempty"`
	Device       string `json:"device,omitempty"`
	VarBindOID   string `json:"varbind_oid,omitempty"`
	VarBindValue string `json:"varbind_value,omitempty"`
	HoldSeconds  int    `json:"hold_seconds,omitempty"`
}

// Hold returns the effective hold duration.
func (m TrapMatch) Hold() time.Duration {
	if m.HoldSeconds <= 0 {
		return DefaultTrapHoldSeconds * time.Second
	}
	return time.Duration(m.HoldSeconds) * time.Second
}

// Rule is an alert rule definition.
type Rule struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`

	// Target: the metric series this rule watches.
	Metric string            `json:"metric"`
	Match  map[string]string `json:"match,omitempty"`

	Type RuleType `json:"type"`

	// Trap parameters (Type == Trap only).
	Trap *TrapMatch `json:"trap,omitempty"`

	// Threshold parameters.
	Comparison Comparison `json:"comparison,omitempty"`
	Threshold  float64    `json:"threshold,omitempty"`

	// Baseline parameters.
	Window      int     `json:"window,omitempty"`      // history samples before evaluating
	Sensitivity float64 `json:"sensitivity,omitempty"` // deviation in standard deviations

	// Firing behavior.
	ForN            int           `json:"for_n,omitempty"`            // consecutive breaching evals before firing (debounce)
	RenotifySeconds int           `json:"renotify_seconds,omitempty"` // re-notify cadence while firing (0 = notify once)
	Severity        Severity      `json:"severity"`
	Channels        []ChannelSpec `json:"channels,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var validComparisons = map[Comparison]bool{GT: true, LT: true, GTE: true, LTE: true, EQ: true, NEQ: true}

// Validate checks a rule's coherence before it is stored or evaluated.
func (r Rule) Validate() error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 200 {
		return fmt.Errorf("alert: name is required (1-200 chars)")
	}
	if r.Type == Trap {
		return r.validateTrap()
	}
	if r.Trap != nil {
		return fmt.Errorf("alert: trap parameters are only valid on a trap rule")
	}
	if strings.TrimSpace(r.Metric) == "" {
		return fmt.Errorf("alert: metric is required")
	}
	// The metric name and match keys are concatenated into a tenant-scoped
	// instant query; a non-identifier here would let a rule inject a second
	// selector and escape the tenant_id pin (G7-1). Reject anything but a bare
	// metric name / label name, and forbid the reserved scoping labels so a
	// caller cannot supply their own tenant_id / __name__ matcher.
	if !promapi.ValidMetricName(r.Metric) {
		return fmt.Errorf("alert: metric must be a bare metric name")
	}
	for k := range r.Match {
		if k == promapi.TenantLabel || k == "__name__" {
			return fmt.Errorf("alert: match key %q is reserved", k)
		}
		if !promapi.ValidLabelName(k) {
			return fmt.Errorf("alert: match key %q is not a valid label name", k)
		}
	}
	switch r.Type {
	case Threshold:
		if !validComparisons[r.Comparison] {
			return fmt.Errorf("alert: comparison must be one of gt,lt,gte,lte,eq,neq")
		}
	case Baseline:
		if r.Window < 2 {
			return fmt.Errorf("alert: baseline window must be >= 2")
		}
		if r.Sensitivity <= 0 {
			return fmt.Errorf("alert: baseline sensitivity must be > 0")
		}
	default:
		return fmt.Errorf("alert: type must be threshold, baseline or trap")
	}
	return r.validateDelivery()
}

// validateDelivery checks the firing behavior and channels every type shares.
func (r Rule) validateDelivery() error {
	if r.ForN < 0 || r.RenotifySeconds < 0 {
		return fmt.Errorf("alert: for_n and renotify_seconds must be non-negative")
	}
	for i, c := range r.Channels {
		switch c.Type {
		case "webhook":
			if strings.TrimSpace(c.URL) == "" {
				return fmt.Errorf("alert: channel %d (webhook) requires a url", i)
			}
		case "email":
			if len(c.Recipients) == 0 {
				return fmt.Errorf("alert: channel %d (email) requires recipients", i)
			}
		default:
			return fmt.Errorf("alert: channel %d type must be webhook or email", i)
		}
	}
	return nil
}

// breaches reports whether value crosses the threshold under the comparison.
func breaches(cmp Comparison, value, threshold float64) bool {
	switch cmp {
	case GT:
		return value > threshold
	case LT:
		return value < threshold
	case GTE:
		return value >= threshold
	case LTE:
		return value <= threshold
	case EQ:
		return value == threshold
	case NEQ:
		return value != threshold
	default:
		return false
	}
}

// validateTrap checks a trap rule: the match is required and bounded, and the
// metric-rule fields that do not apply are empty (a trap rule's metric is
// TrapMetric, set by NormalizeTrapRule).
func (r Rule) validateTrap() error {
	if r.Trap == nil {
		return fmt.Errorf("alert: a trap rule requires trap.trap_oid")
	}
	m := *r.Trap
	if !validOID(m.TrapOID) {
		return fmt.Errorf("alert: trap.trap_oid must be a dotted-decimal OID (at most %d characters)", maxTrapOIDLength)
	}
	if m.ClearTrapOID != "" {
		if !validOID(m.ClearTrapOID) {
			return fmt.Errorf("alert: trap.clear_trap_oid must be a dotted-decimal OID")
		}
		if normalizeOID(m.ClearTrapOID) == normalizeOID(m.TrapOID) {
			return fmt.Errorf("alert: trap.clear_trap_oid must differ from trap.trap_oid")
		}
	}
	if len(m.Device) > maxTrapDeviceLength || strings.TrimSpace(m.Device) != m.Device {
		return fmt.Errorf("alert: trap.device must be an exact device address (at most %d characters)", maxTrapDeviceLength)
	}
	if m.VarBindOID == "" && m.VarBindValue != "" {
		return fmt.Errorf("alert: trap.varbind_value requires trap.varbind_oid")
	}
	if m.VarBindOID != "" && !validOID(m.VarBindOID) {
		return fmt.Errorf("alert: trap.varbind_oid must be a dotted-decimal OID")
	}
	if len(m.VarBindValue) > maxTrapVarBindValue {
		return fmt.Errorf("alert: trap.varbind_value must be at most %d bytes", maxTrapVarBindValue)
	}
	if m.HoldSeconds != 0 && (m.HoldSeconds < MinTrapHoldSeconds || m.HoldSeconds > MaxTrapHoldSeconds) {
		return fmt.Errorf("alert: trap.hold_seconds must be between %d and %d", MinTrapHoldSeconds, MaxTrapHoldSeconds)
	}
	if r.Metric != "" && r.Metric != TrapMetric {
		return fmt.Errorf("alert: a trap rule watches stored traps; metric must be empty or %s", TrapMetric)
	}
	if len(r.Match) > 0 {
		return fmt.Errorf("alert: a trap rule matches through trap.device and trap.varbind_oid, not match labels")
	}
	return r.validateDelivery()
}

// NormalizeTrapRule gives a validated trap rule its canonical form: the fixed
// TrapMetric, a ">= 1" condition on the rule's active-trap indicator (what the
// evaluation receipts and webhook payloads report), leading-dot OIDs and the
// default hold. It is a no-op for other rule types.
func NormalizeTrapRule(r *Rule) {
	if r == nil || r.Type != Trap || r.Trap == nil {
		return
	}
	r.Metric = TrapMetric
	r.Match = nil
	r.Comparison, r.Threshold = GTE, 1
	r.Window, r.Sensitivity = 0, 0
	m := *r.Trap
	m.TrapOID = normalizeOID(m.TrapOID)
	m.ClearTrapOID = normalizeOID(m.ClearTrapOID)
	m.VarBindOID = normalizeOID(m.VarBindOID)
	if m.HoldSeconds == 0 {
		m.HoldSeconds = DefaultTrapHoldSeconds
	}
	r.Trap = &m
}

func normalizeOID(oid string) string {
	oid = strings.TrimSpace(oid)
	if oid == "" {
		return ""
	}
	return "." + strings.TrimPrefix(oid, ".")
}

func validOID(oid string) bool {
	if oid == "" || len(oid) > maxTrapOIDLength {
		return false
	}
	s := strings.TrimPrefix(oid, ".")
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" || strings.Trim(part, "0123456789") != "" {
			return false
		}
	}
	return true
}
