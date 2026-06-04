package alert

import (
	"sort"
	"strings"
	"time"
)

// seriesState tracks one rule's evaluation state for one time-series (identified
// by its label set), so debounce (ForN), firing, and dedupe/renotify are
// per-series rather than per-rule.
type seriesState struct {
	breachCount  int
	firing       bool
	lastNotified time.Time
	base         *baseline // baseline rules only

	// Rendered state for the active-alert surface (S-FE1), written on each
	// evaluation so the API reflects engine truth.
	ruleID     string
	ruleName   string
	severity   Severity
	metric     string
	labels     map[string]string
	lastValue  float64
	lastReason string
	since      time.Time // first firing of the current episode
	lastSeen   time.Time // last evaluation of this series

	// Operator actions (S-FE1): cleared automatically on resolve.
	silencedUntil time.Time
	ackedBy       string
	ackedAt       time.Time
}

// fingerprint is a stable key for a label set.
func fingerprint(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
		b.WriteByte(';')
	}
	return b.String()
}

func stateKey(ruleID string, labels map[string]string) string {
	return ruleID + "|" + fingerprint(labels)
}
