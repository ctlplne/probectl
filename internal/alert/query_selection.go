// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"encoding/hex"
	"maps"
	"sort"
	"strings"
	"time"
)

// QuerySelection is operation-local completion metadata from an authenticated
// source, not a serialized grant. Only a fully admitted current source read may
// let an absent group resolve. A failed/partial read returns no selection.
type QuerySelection struct {
	TenantID, RuleID, Binding string
	At                        time.Time
	Complete                  bool
}

func (q *QuerySelection) Validate(rule Rule) error {
	if q == nil || !q.Complete || q.At.IsZero() || q.TenantID != rule.TenantID || q.RuleID != rule.ID || !selectedSourceMetric(rule.Metric) || !canonicalQueryID(q.TenantID) || !canonicalQueryID(q.RuleID) {
		return ErrQueryGroups
	}
	decoded, err := hex.DecodeString(q.Binding)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != q.Binding {
		return ErrQueryGroups
	}
	return nil
}

// A complete source selection can resolve durable episodes whose departure
// happened before a restart. It also bounds the live map to the current group
// set: resolved departed groups are removed after normal delivery/cleanup.
func (en *Engine) completeQuerySamples(rule Rule, read RuleMetricRead) ([]Sample, map[string]bool, error) {
	if err := read.QuerySelection.Validate(rule); err != nil {
		return nil, nil, err
	}
	seen := make(map[string]bool, len(read.Samples))
	departed := map[string]bool{}
	samples := append([]Sample(nil), read.Samples...)
	for _, sample := range samples {
		if !selectedSampleLabels(rule.Metric, sample.Labels) || (sample.Value != 0 && sample.Value != 1) {
			return nil, nil, ErrQueryGroups
		}
		key := stateKey(rule.ID, sample.Labels)
		if seen[key] {
			return nil, nil, ErrQueryGroups
		}
		seen[key] = true
	}
	missing := map[string]map[string]string{}
	prefix := rule.ID + "|"
	en.mu.Lock()
	for key, state := range en.states {
		if state.ruleID == rule.ID && !seen[key] {
			missing[key] = maps.Clone(state.labels)
		}
	}
	for key := range en.restoredNotify {
		if strings.HasPrefix(key, prefix) && !seen[key] {
			missing[key] = labelsFromStateKey(key, prefix)
		}
	}
	en.mu.Unlock()
	keys := make([]string, 0, len(missing))
	for key := range missing {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		labels := missing[key]
		if !selectedSampleLabels(rule.Metric, labels) {
			return nil, nil, ErrQueryGroups
		}
		departed[key] = true
		reason := "group absent from the complete saved-query selection"
		if rule.Metric == PathHealthMetric {
			reason = "port source absent from the complete current path selection"
		}
		samples = append(samples, Sample{Labels: labels, Reason: reason})
	}
	en.restoreQueryEpisodes(rule, samples)
	return samples, departed, nil
}

func (en *Engine) restoreQueryEpisodes(rule Rule, samples []Sample) {
	en.mu.Lock()
	defer en.mu.Unlock()
	for _, sample := range samples {
		key := stateKey(rule.ID, sample.Labels)
		notified, ok := en.restoredNotify[key]
		if !ok {
			continue
		}
		state := en.stateForLocked(rule, sample.Labels)
		state.firing, state.since, state.lastNotified = true, notified.FiringSince, notified.LastNotified
		if op, ok := en.restored[key]; ok {
			state.silencedUntil, state.ackedBy, state.ackedAt = op.SilencedUntil, op.AckedBy, op.AckedAt
		}
		delete(en.restoredNotify, key)
	}
}

func selectedSourceMetric(metric string) bool {
	return metric == QueryMetric || metric == PathHealthMetric
}

func selectedSampleLabels(metric string, labels map[string]string) bool {
	parent, group := "query_view_id", "query_group"
	if metric == PathHealthMetric {
		parent, group = "path_test_id", "path_health_group"
	} else if metric != QueryMetric {
		return false
	}
	if len(labels) != 2 || !canonicalQueryID(labels[parent]) {
		return false
	}
	key := labels[group]
	decoded, err := hex.DecodeString(key)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == key
}

func (en *Engine) pruneDepartedQueryGroups(departed map[string]bool) {
	if len(departed) == 0 {
		return
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	for key := range departed {
		state := en.states[key]
		if state != nil && !state.firing && state.breachCount == 0 {
			delete(en.states, key)
		}
	}
}

// ValidQueryGroupKey validates an opaque handle only; a handle never grants
// access to a source. Current tenant/source authorization remains mandatory.
func ValidQueryGroupKey(key string) bool {
	if len(key) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(key)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == key
}

// QueryGroupInspection is a fresh manual source read, never a historical
// firing receipt and never an instruction to advance baseline or schedule.
type QueryGroupInspection struct {
	Kind                string            `json:"kind"`
	RuleID              string            `json:"rule_id"`
	GroupKey            string            `json:"group_key"`
	ViewID              string            `json:"view_id"`
	ViewVersion         string            `json:"view_version"`
	At                  time.Time         `json:"at"`
	From                time.Time         `json:"from"`
	To                  time.Time         `json:"to"`
	Present             bool              `json:"present"`
	Dimensions          map[string]string `json:"dimensions,omitempty"`
	ExactValue          string            `json:"exact_value,omitempty"`
	Condition           QueryCondition    `json:"condition"`
	ConditionMet        bool              `json:"condition_met"`
	BaselineInitialized bool              `json:"baseline_initialized"`
}
