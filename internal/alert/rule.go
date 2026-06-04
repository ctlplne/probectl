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
)

// RuleType selects the evaluation strategy.
type RuleType string

const (
	// Threshold fires when an aggregated value crosses a fixed bound.
	Threshold RuleType = "threshold"
	// Baseline fires when a value deviates from its recent statistical baseline
	// (anomaly detection); it needs history and warms up on cold start.
	Baseline RuleType = "baseline"
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
	if strings.TrimSpace(r.Metric) == "" {
		return fmt.Errorf("alert: metric is required")
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
		return fmt.Errorf("alert: type must be threshold or baseline")
	}
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
