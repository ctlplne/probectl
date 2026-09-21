// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package support is the core supportability layer (S-EE4, F35): deep health
// checks, a self-monitoring metric snapshot, and a secret-stripped support
// bundle. It is CORE by the ratified editions decision — better community bug
// reports serve everyone; the support org / SLA is a commercial contract, not
// code.
//
// The non-negotiable safety property (docs/guardrails.md G7-6): a support
// bundle NEVER contains secrets, credentials, or PII. The config snapshot is
// an allowlist (config.Redacted), and the bundle additionally SCRUBS any
// known-sensitive value the caller passes — defense in depth, so an accidental
// inclusion still cannot leak.
package support

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Status is a component's health.
type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
	StatusDown     Status = "down"
)

// FindingSeverity is the operator-facing urgency of a readiness finding.
type FindingSeverity string

const (
	FindingWarning  FindingSeverity = "warning"
	FindingCritical FindingSeverity = "critical"
)

// ActionKind describes a safe, local next action. Diagnostics never executes
// remediation: it can only navigate within the self-hosted UI or download a
// local artifact.
type ActionKind string

const (
	ActionNavigate ActionKind = "navigate"
	ActionDownload ActionKind = "download"
)

// LocalAction is a non-executing next step within this deployment.
type LocalAction struct {
	Label string     `json:"label"`
	Href  string     `json:"href"`
	Kind  ActionKind `json:"kind"`
}

// ReadinessFinding turns one unhealthy component check into a deterministic,
// locally actionable operator task. Scope is currently always "deployment":
// these checks expose redacted control-plane state, never tenant telemetry.
type ReadinessFinding struct {
	ID         string          `json:"id"`
	Component  string          `json:"component"`
	Scope      string          `json:"scope"`
	Severity   FindingSeverity `json:"severity"`
	ObservedAt time.Time       `json:"observed_at"`
	Summary    string          `json:"summary"`
	Evidence   string          `json:"evidence"`
	NextAction LocalAction     `json:"next_action"`
}

// rank orders statuses worst-last so the aggregate is the worst component.
func (s Status) rank() int {
	switch s {
	case StatusOK:
		return 0
	case StatusDegraded:
		return 1
	default:
		return 2
	}
}

// Check is one component's deep-health result.
type Check struct {
	Name    string            `json:"name"`
	Status  Status            `json:"status"`
	Detail  string            `json:"detail,omitempty"`
	Finding *ReadinessFinding `json:"finding,omitempty"`
}

// CheckFunc runs a single component check. It must be quick and must never
// surface secrets in Detail.
type CheckFunc func(ctx context.Context) Check

// Health is the aggregate deep-health report.
type Health struct {
	Status    Status    `json:"status"` // the worst component
	Checks    []Check   `json:"checks"`
	CheckedAt time.Time `json:"checked_at"`
}

// RunChecks runs every registered check (sorted by name for a stable report)
// and aggregates to the worst status. An empty set is StatusOK.
func RunChecks(ctx context.Context, checks map[string]CheckFunc, now func() time.Time) Health {
	if now == nil {
		now = time.Now
	}
	names := make([]string, 0, len(checks))
	for n := range checks {
		names = append(names, n)
	}
	sort.Strings(names)

	h := Health{Status: StatusOK, CheckedAt: now().UTC()}
	for _, n := range names {
		c := checks[n](ctx)
		if c.Name == "" {
			c.Name = n
		}
		if c.Status != StatusOK && c.Status != StatusDegraded && c.Status != StatusDown {
			c.Status = StatusDown
			c.Detail = "health check returned an invalid status"
		}
		c.normalizeFinding(h.CheckedAt)
		h.Checks = append(h.Checks, c)
		if c.Status.rank() > h.Status.rank() {
			h.Status = c.Status
		}
	}
	return h
}

// PingCheck builds a check from a context-cancellable ping (e.g. a DB pool).
// A nil ping reports down ("not configured"); a slow ping is bounded by the
// caller's context.
func PingCheck(name string, ping func(ctx context.Context) error) CheckFunc {
	return func(ctx context.Context) Check {
		if ping == nil {
			return Check{Name: name, Status: StatusDown, Detail: "not configured"}
		}
		if err := ping(ctx); err != nil {
			// Dependency errors can carry DSNs, hostnames, or credentials. The
			// operator gets a stable public fact; the support bundle carries
			// the rest of the already-redacted local context.
			return Check{Name: name, Status: StatusDown, Detail: "health check failed"}
		}
		return Check{Name: name, Status: StatusOK}
	}
}

// NewReadinessFinding supplies component-specific operator guidance. RunChecks
// fills the component, scope, severity, and observation time from trusted local
// health state so callers cannot create a contradictory result.
func NewReadinessFinding(id, summary, evidence string, action LocalAction) *ReadinessFinding {
	return &ReadinessFinding{
		ID:         id,
		Summary:    summary,
		Evidence:   evidence,
		NextAction: action,
	}
}

func (c *Check) normalizeFinding(observedAt time.Time) {
	if c.Status == StatusOK {
		c.Finding = nil
		return
	}

	if c.Finding == nil {
		c.Finding = &ReadinessFinding{}
	}
	f := c.Finding
	f.Component = c.Name
	f.Scope = "deployment"
	f.ObservedAt = observedAt
	if c.Status == StatusDown {
		f.Severity = FindingCritical
	} else {
		f.Severity = FindingWarning
	}
	if !validFindingID(f.ID) {
		f.ID = "readiness." + stableIdentifier(c.Name)
	}
	if strings.TrimSpace(f.Summary) == "" {
		f.Summary = c.Name + " is " + string(c.Status)
	}
	if strings.TrimSpace(f.Evidence) == "" {
		f.Evidence = "The local " + c.Name + " health check reported " + string(c.Status) + "."
	}
	f.Summary = truncateRunes(strings.TrimSpace(f.Summary), 160)
	f.Evidence = truncateRunes(strings.TrimSpace(f.Evidence), 512)
	f.NextAction = normalizeAction(f.NextAction)
}

func validFindingID(id string) bool {
	if id == "" || len(id) > 96 || !strings.HasPrefix(id, "readiness.") {
		return false
	}
	for _, r := range id {
		if !isASCIILowerOrDigit(r) && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func stableIdentifier(value string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		if isASCIILowerOrDigit(r) || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "component"
	}
	return b.String()
}

func isASCIILowerOrDigit(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
}

func normalizeAction(action LocalAction) LocalAction {
	if action.Kind != ActionNavigate && action.Kind != ActionDownload {
		action.Kind = ActionNavigate
	}
	action.Href = truncateRunes(strings.TrimSpace(action.Href), 256)
	parsed, err := url.Parse(action.Href)
	if err != nil ||
		parsed.IsAbs() ||
		parsed.Host != "" ||
		!strings.HasPrefix(parsed.Path, "/") ||
		strings.HasPrefix(action.Href, "//") ||
		strings.Contains(action.Href, `\`) {
		return LocalAction{
			Label: "Review diagnostics",
			Href:  "/admin#support-bundle",
			Kind:  ActionNavigate,
		}
	}
	action.Label = truncateRunes(strings.TrimSpace(action.Label), 80)
	if action.Label == "" {
		action.Label = "Review diagnostics"
	}
	return action
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
