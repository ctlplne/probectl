// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const agentCoverageFreshness = 5 * time.Minute

type coverageNextAction struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Href  string `json:"href"`
}

// coverageMatrixItem is one enabled test at one operator-declared site/region.
// A missing compatible agent deliberately remains a row with zero vantages and
// status=uncovered; it is never collapsed into a misleading healthy zero.
type coverageMatrixItem struct {
	TestID                  string              `json:"test_id"`
	TestName                string              `json:"test_name"`
	Region                  string              `json:"region"`
	Site                    string              `json:"site"`
	AgentReadiness          string              `json:"agent_readiness"`
	AgentCount              int                 `json:"agent_count"`
	ReadyAgentCount         int                 `json:"ready_agent_count"`
	ProbeFamily             string              `json:"probe_family"`
	Target                  string              `json:"target"`
	LastEvidenceAt          *time.Time          `json:"last_evidence_at,omitempty"`
	IndependentVantageCount int                 `json:"independent_vantage_count"`
	StaleAfterSeconds       int                 `json:"stale_after_seconds"`
	Status                  string              `json:"status"`
	NextAction              *coverageNextAction `json:"next_action,omitempty"`
}

type coverageGroup struct {
	item        coverageMatrixItem
	evidenceIDs map[string]struct{}
}

func buildCoverageMatrix(candidates []store.CoverageCandidate, results []ResultView, now time.Time) []coverageMatrixItem {
	evidence := make(map[string]ResultView, len(results))
	for _, result := range results {
		key := result.Type + "\x00" + result.Target + "\x00" + result.AgentID
		if previous, ok := evidence[key]; !ok || result.ObservedAt.After(previous.ObservedAt) {
			evidence[key] = result
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
				evidenceIDs: map[string]struct{}{},
			}
			groups[key] = group
		}
		if candidate.AgentID == "" {
			continue
		}
		group.item.AgentCount++
		if candidate.AgentStatus == "online" && candidate.LastSeenAt != nil &&
			!candidate.LastSeenAt.Before(now.Add(-agentCoverageFreshness)) {
			group.item.ReadyAgentCount++
		}
		result, ok := evidence[candidate.ProbeFamily+"\x00"+candidate.Target+"\x00"+candidate.AgentID]
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
	evidenceRunning := s.latestResults != nil
	if evidenceRunning {
		results = s.latestResults.List(tenantID)
	}
	now := time.Now().UTC()
	items := buildCoverageMatrix(candidates, results, now)
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "as_of": now, "evidence_running": evidenceRunning,
		"candidate_limit": limit, "truncated": truncated,
	})
	return nil
}
