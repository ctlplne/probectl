// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

	// lastEvaluationState deduplicates the durable receipt stream to state
	// transitions. Baseline warmup is the one exception: each bounded warmup
	// step records its progress.
	lastEvaluationState EvaluationState

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
