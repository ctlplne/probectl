// Package support is the core supportability layer (S-EE4, F35): deep health
// checks, a self-monitoring metric snapshot, and a secret-stripped support
// bundle. It is CORE by the ratified editions decision — better community bug
// reports serve everyone; the support org / SLA is a commercial contract, not
// code.
//
// The non-negotiable safety property (CLAUDE.md §7 guardrail 6): a support
// bundle NEVER contains secrets, credentials, or PII. The config snapshot is
// an allowlist (config.Redacted), and the bundle additionally SCRUBS any
// known-sensitive value the caller passes — defense in depth, so an accidental
// inclusion still cannot leak.
package support

import (
	"context"
	"sort"
	"time"
)

// Status is a component's health.
type Status string

const (
	StatusOK       Status = "ok"
	StatusDegraded Status = "degraded"
	StatusDown     Status = "down"
)

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
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
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
			return Check{Name: name, Status: StatusDown, Detail: err.Error()}
		}
		return Check{Name: name, Status: StatusOK}
	}
}
