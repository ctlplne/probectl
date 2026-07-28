// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/otel"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const agentCoverageFreshness = 5 * time.Minute

const (
	cadenceMinimumWindow     = 5 * time.Minute
	cadenceMaximumWindow     = 24 * time.Hour
	cadenceWindowIntervals   = 6
	cadenceMinimumRoundCount = 3
)

type coverageNextAction struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Href  string `json:"href"`
}

// executionCadenceReceipt is read-only evidence about locally observed probe
// execution. CurrentAssignmentVerified is deliberately always false: the
// control plane does not push or read the agent's local YAML, so an exact result
// proves past execution, not that the assignment remains installed now.
type executionCadenceReceipt struct {
	State                     string `json:"state"`
	Reason                    string `json:"reason"`
	Attribution               string `json:"attribution"`
	ConfiguredIntervalSeconds int    `json:"configured_interval_seconds"`
	WindowSeconds             int    `json:"window_seconds"`
	ExpectedRounds            int    `json:"expected_rounds"`
	ObservedRounds            int    `json:"observed_rounds"`
	MissedRounds              int    `json:"missed_rounds"`
	MaxGapSeconds             int    `json:"max_gap_seconds"`
	ObservedAgentCount        int    `json:"observed_agent_count"`
	HistoryComplete           bool   `json:"history_complete"`
	CurrentAssignmentVerified bool   `json:"current_assignment_verified"`
}

// coverageMatrixItem is one enabled test at one operator-declared site/region.
// A missing compatible agent deliberately remains a row with zero vantages and
// status=uncovered; it is never collapsed into a misleading healthy zero.
type coverageMatrixItem struct {
	TestID                  string                  `json:"test_id"`
	TestName                string                  `json:"test_name"`
	Region                  string                  `json:"region"`
	Site                    string                  `json:"site"`
	AgentReadiness          string                  `json:"agent_readiness"`
	AgentCount              int                     `json:"agent_count"`
	ReadyAgentCount         int                     `json:"ready_agent_count"`
	ProbeFamily             string                  `json:"probe_family"`
	Target                  string                  `json:"target"`
	LastEvidenceAt          *time.Time              `json:"last_evidence_at,omitempty"`
	IndependentVantageCount int                     `json:"independent_vantage_count"`
	StaleAfterSeconds       int                     `json:"stale_after_seconds"`
	Status                  string                  `json:"status"`
	ExecutionCadence        executionCadenceReceipt `json:"execution_cadence"`
	NextAction              *coverageNextAction     `json:"next_action,omitempty"`
}

type coverageGroup struct {
	item            coverageMatrixItem
	intervalSeconds int
	evidenceIDs     map[string]struct{}
	agentIDs        map[string]struct{}
}

func buildCoverageMatrix(
	candidates []store.CoverageCandidate,
	results []ResultView,
	recent []ResultView,
	recentIncompleteThrough time.Time,
	evidenceRunning bool,
	now time.Time,
) []coverageMatrixItem {
	exactEvidence := make(map[string]ResultView, len(results))
	legacyEvidence := make(map[string]ResultView, len(results))
	for _, result := range results {
		if testID := result.Attributes[otel.AttrTestID]; testID != "" {
			key := testID + "\x00" + result.AgentID
			if previous, ok := exactEvidence[key]; !ok || result.ObservedAt.After(previous.ObservedAt) {
				exactEvidence[key] = result
			}
			continue
		}
		key := result.Type + "\x00" + result.Target + "\x00" + result.AgentID
		if previous, ok := legacyEvidence[key]; !ok || result.ObservedAt.After(previous.ObservedAt) {
			legacyEvidence[key] = result
		}
	}

	groups := map[string]*coverageGroup{}
	for _, candidate := range candidates {
		key := candidate.TestID + "\x00" + candidate.Region + "\x00" + candidate.Site
		group, ok := groups[key]
		if !ok {
			staleAfter := max(candidate.IntervalSeconds*3, int((5 * time.Minute).Seconds()))
			group = &coverageGroup{
				item: coverageMatrixItem{
					TestID: candidate.TestID, TestName: candidate.TestName,
					Region: candidate.Region, Site: candidate.Site,
					ProbeFamily: candidate.ProbeFamily, Target: candidate.Target,
					AgentReadiness: "unavailable", StaleAfterSeconds: staleAfter,
					Status: "uncovered",
				},
				intervalSeconds: candidate.IntervalSeconds,
				evidenceIDs:     map[string]struct{}{},
				agentIDs:        map[string]struct{}{},
			}
			groups[key] = group
		}
		if candidate.AgentID == "" {
			continue
		}
		group.agentIDs[candidate.AgentID] = struct{}{}
		group.item.AgentCount++
		if candidate.AgentStatus == "online" && candidate.LastSeenAt != nil &&
			!candidate.LastSeenAt.Before(now.Add(-agentCoverageFreshness)) {
			group.item.ReadyAgentCount++
		}
		result, ok := exactEvidence[candidate.TestID+"\x00"+candidate.AgentID]
		if ok && (result.Type != candidate.ProbeFamily || result.Target != candidate.Target) {
			ok = false
		}
		if !ok {
			result, ok = legacyEvidence[candidate.ProbeFamily+"\x00"+candidate.Target+"\x00"+candidate.AgentID]
		}
		if !ok {
			continue
		}
		group.evidenceIDs[candidate.AgentID] = struct{}{}
		if group.item.LastEvidenceAt == nil || result.ObservedAt.After(*group.item.LastEvidenceAt) {
			at := result.ObservedAt
			group.item.LastEvidenceAt = &at
		}
	}

	items := make([]coverageMatrixItem, 0, len(groups))
	for _, group := range groups {
		item := group.item
		item.ExecutionCadence = buildExecutionCadence(
			item.TestID,
			item.ProbeFamily,
			item.Target,
			group.intervalSeconds,
			group.agentIDs,
			recent,
			recentIncompleteThrough,
			evidenceRunning,
			now,
		)
		item.IndependentVantageCount = len(group.evidenceIDs)
		switch {
		case item.AgentCount == 0 || item.ReadyAgentCount == 0:
			item.AgentReadiness = "unavailable"
		case item.ReadyAgentCount < item.AgentCount:
			item.AgentReadiness = "degraded"
		default:
			item.AgentReadiness = "ready"
		}
		switch {
		case item.IndependentVantageCount == 0:
			item.Status = "uncovered"
		case item.LastEvidenceAt == nil ||
			item.LastEvidenceAt.Before(now.Add(-time.Duration(item.StaleAfterSeconds)*time.Second)):
			item.Status = "stale"
		case item.IndependentVantageCount == 1:
			item.Status = "non_redundant"
		default:
			item.Status = "covered"
		}
		if item.Status != "covered" {
			if item.AgentCount == 0 || item.AgentReadiness == "unavailable" {
				item.NextAction = &coverageNextAction{
					Kind: "enroll_vantage", Label: "Enroll or restore a vantage", Href: "/admin",
				}
			} else {
				item.NextAction = &coverageNextAction{
					Kind: "author_test", Label: "Author another test", Href: "/targets?create=test",
				}
			}
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Status != items[j].Status {
			return coverageStatusRank(items[i].Status) < coverageStatusRank(items[j].Status)
		}
		if items[i].Region != items[j].Region {
			return items[i].Region < items[j].Region
		}
		if items[i].Site != items[j].Site {
			return items[i].Site < items[j].Site
		}
		return items[i].TestID < items[j].TestID
	})
	return items
}

func buildExecutionCadence(
	testID, probeFamily, target string,
	intervalSeconds int,
	agentIDs map[string]struct{},
	recent []ResultView,
	recentIncompleteThrough time.Time,
	evidenceRunning bool,
	now time.Time,
) executionCadenceReceipt {
	window := time.Duration(intervalSeconds*cadenceWindowIntervals) * time.Second
	if window < cadenceMinimumWindow {
		window = cadenceMinimumWindow
	}
	if window > cadenceMaximumWindow {
		window = cadenceMaximumWindow
	}
	receipt := executionCadenceReceipt{
		State:                     "unknown",
		Reason:                    "evidence_unwired",
		Attribution:               "none",
		ConfiguredIntervalSeconds: intervalSeconds,
		WindowSeconds:             int(window.Seconds()),
		CurrentAssignmentVerified: false,
	}
	if !evidenceRunning {
		return receipt
	}
	cutoff := now.Add(-window)
	receipt.HistoryComplete = recentIncompleteThrough.IsZero() || recentIncompleteThrough.Before(cutoff)

	byAgent := make(map[string][]ResultView)
	legacyMatch := false
	futureEvidence := false
	definitionMismatch := false
	for _, result := range recent {
		if _, candidate := agentIDs[result.AgentID]; !candidate {
			continue
		}
		resultTestID := result.Attributes[otel.AttrTestID]
		if resultTestID == "" {
			if result.Type == probeFamily && result.Target == target {
				legacyMatch = true
			}
			continue
		}
		if resultTestID != testID {
			continue
		}
		receipt.Attribution = "exact_test_id"
		if result.ObservedAt.After(now) {
			futureEvidence = true
			continue
		}
		if result.Type != probeFamily || result.Target != target {
			definitionMismatch = true
			continue
		}
		byAgent[result.AgentID] = append(byAgent[result.AgentID], result)
	}
	if futureEvidence {
		receipt.Reason = "future_evidence_timestamp"
		return receipt
	}
	if definitionMismatch {
		receipt.Reason = "definition_mismatch"
		return receipt
	}
	if len(byAgent) == 0 {
		if legacyMatch {
			receipt.Reason = "legacy_or_unattributed_evidence"
			return receipt
		}
		if !receipt.HistoryComplete {
			receipt.Reason = "history_truncated"
			return receipt
		}
		receipt.State = "never_observed"
		receipt.Reason = "no_exact_test_evidence"
		return receipt
	}

	interval := time.Duration(intervalSeconds) * time.Second
	if interval <= 0 {
		receipt.Reason = "invalid_configured_interval"
		return receipt
	}
	grace := interval / 2
	if grace < 5*time.Second {
		grace = 5 * time.Second
	}
	seenResults := make(map[string]struct{})
	intervalMismatch := false
	missingScheduleMetadata := false
	maxGap := time.Duration(0)

	for agentID, agentResults := range byAgent {
		sort.Slice(agentResults, func(i, j int) bool {
			return agentResults[i].ObservedAt.Before(agentResults[j].ObservedAt)
		})
		receipt.ObservedAgentCount++
		inWindow := make([]ResultView, 0, len(agentResults))
		var lastBeforeWindow *ResultView
		for i := range agentResults {
			result := agentResults[i]
			reported, err := strconv.ParseFloat(result.Attributes[otel.AttrTestInterval], 64)
			if err != nil || reported <= 0 {
				missingScheduleMetadata = true
				continue
			}
			if math.Abs(reported-float64(intervalSeconds)) > 0.001 {
				intervalMismatch = true
				continue
			}
			key := result.ResultID
			if key == "" {
				key = agentID + "\x00" + result.ObservedAt.UTC().Format(time.RFC3339Nano)
			} else {
				key = agentID + "\x00" + key
			}
			if _, duplicate := seenResults[key]; duplicate {
				continue
			}
			seenResults[key] = struct{}{}
			if result.ObservedAt.Before(cutoff) {
				priorResult := result
				lastBeforeWindow = &priorResult
				continue
			}
			inWindow = append(inWindow, result)
		}

		receipt.ObservedRounds += len(inWindow)
		var previous time.Time
		if lastBeforeWindow != nil {
			previous = lastBeforeWindow.ObservedAt
			if previous.Before(cutoff) {
				previous = cutoff
			}
		}
		for _, result := range inWindow {
			if !previous.IsZero() {
				gap := result.ObservedAt.Sub(previous)
				maxGap = max(maxGap, gap)
				receipt.MissedRounds += missedCadenceRounds(gap, interval, grace)
			}
			previous = result.ObservedAt
		}
		if previous.IsZero() {
			// Exact evidence exists but nothing landed inside this bounded
			// window. Count only the configured window, not the unbounded age
			// since the historical observation.
			previous = cutoff
		}
		tail := now.Sub(previous)
		maxGap = max(maxGap, tail)
		receipt.MissedRounds += missedCadenceRounds(tail, interval, grace)
	}

	if intervalMismatch {
		receipt.MissedRounds = 0
		receipt.Reason = "interval_mismatch"
		return receipt
	}
	if missingScheduleMetadata {
		receipt.MissedRounds = 0
		receipt.Reason = "legacy_schedule_metadata"
		return receipt
	}
	receipt.MaxGapSeconds = int(math.Ceil(maxGap.Seconds()))
	receipt.ExpectedRounds = receipt.ObservedRounds + receipt.MissedRounds
	switch {
	case receipt.MissedRounds > 0:
		receipt.State = "gaps_observed"
		receipt.Reason = "missed_rounds"
	case !receipt.HistoryComplete:
		receipt.Reason = "history_truncated"
	case receipt.ObservedRounds < cadenceMinimumRoundCount:
		receipt.Reason = "insufficient_history"
	default:
		receipt.State = "on_cadence"
		receipt.Reason = "on_cadence"
	}
	return receipt
}

func missedCadenceRounds(gap, interval, grace time.Duration) int {
	if gap <= grace || interval <= 0 {
		return 0
	}
	adjusted := gap - grace
	if adjusted <= 0 {
		return 0
	}
	rounds := int((adjusted - time.Nanosecond) / interval)
	return max(rounds, 0)
}

func coverageStatusRank(status string) int {
	switch status {
	case "uncovered":
		return 0
	case "stale":
		return 1
	case "non_redundant":
		return 2
	default:
		return 3
	}
}

// handleCoverageMatrix serves a bounded, read-only, tenant-local view. The
// caller needs both test.read (route gate) and agent.read because a row combines
// test definitions with agent placement/readiness metadata.
func (s *Server) handleCoverageMatrix(w http.ResponseWriter, r *http.Request) error {
	principal := auth.PrincipalFrom(r.Context())
	if principal == nil || !principal.Permissions[permAgentRead] {
		return apierror.Forbidden("missing permission: " + permAgentRead)
	}
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit := intQuery(r, "limit", store.DefaultCoverageCandidateLimit)
	if limit <= 0 || limit > store.DefaultCoverageCandidateLimit {
		limit = store.DefaultCoverageCandidateLimit
	}

	var candidates []store.CoverageCandidate
	if err := s.inTenant(r, func(ctx context.Context, scope tenancy.Scope) error {
		rows, queryErr := (store.Agents{}).CoverageCandidates(ctx, scope, limit+1)
		candidates = rows
		return queryErr
	}); err != nil {
		return err
	}
	truncated := len(candidates) > limit
	if truncated {
		candidates = candidates[:limit]
	}
	results := []ResultView{}
	recent := []ResultView{}
	var recentIncompleteThrough time.Time
	evidenceRunning := s.latestResults != nil
	if evidenceRunning {
		results = s.latestResults.List(tenantID)
		recent, recentIncompleteThrough = s.latestResults.RecentSnapshot(tenantID)
	}
	now := time.Now().UTC()
	items := buildCoverageMatrix(
		candidates,
		results,
		recent,
		recentIncompleteThrough,
		evidenceRunning,
		now,
	)
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "as_of": now, "evidence_running": evidenceRunning,
		"candidate_limit": limit, "truncated": truncated,
	})
	return nil
}
