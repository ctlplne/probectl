// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

const (
	defaultCoverageDebtEntityLimit = 500
	maxCoverageDebtEntityLimit     = 500
	coverageDebtPlaneCount         = 5
	coverageDebtStaleAfter         = 15 * time.Minute
	coverageDebtFutureSkew         = 5 * time.Minute
)

var coverageDebtPlanes = [...]string{"synthetic", "path", "flow", "routing", "device"}

type coverageDebtAction struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Href  string `json:"href"`
}

// coverageDebtItem is a flat entity/site × signal-plane row. A flat contract
// keeps the safety bound obvious and lets CLI/UI clients filter without
// interpreting a sparse dynamic object.
type coverageDebtItem struct {
	EntityID           string             `json:"entity_id"`
	EntityKind         string             `json:"entity_kind"`
	Label              string             `json:"label"`
	Region             string             `json:"region,omitempty"`
	Site               string             `json:"site,omitempty"`
	Plane              string             `json:"plane"`
	State              string             `json:"state"`
	ObservedAt         *time.Time         `json:"observed_at,omitempty"`
	EvidenceAgeSeconds *int               `json:"evidence_age_seconds,omitempty"`
	StaleAfterSeconds  int                `json:"stale_after_seconds"`
	EvidenceBasis      string             `json:"evidence_basis"`
	EvidenceRef        string             `json:"evidence_ref,omitempty"`
	NextAction         coverageDebtAction `json:"next_action"`
}

type coverageDebtProducer struct {
	Plane           string `json:"plane"`
	RegisteredCount int    `json:"registered_count"`
	RuntimeRunning  bool   `json:"runtime_running"`
	EvidenceCount   int    `json:"evidence_count"`
	Status          string `json:"status"`
}

type coverageDebtEntity struct {
	id       string
	kind     string
	label    string
	region   string
	site     string
	evidence map[string]coverageDebtEvidence
}

type coverageDebtEvidence struct {
	at         time.Time
	staleAfter time.Duration
	basis      string
	ref        string
	expected   bool
}

type coverageDebtBuildOptions struct {
	now                 time.Time
	evidenceRunning     bool
	topologyRunning     bool
	candidatesTruncated bool
	resultsTruncated    bool
	entityLimit         int
}

type coverageDebtBuildResult struct {
	items             []coverageDebtItem
	entitiesTruncated bool
	topologyTruncated bool
	evidenceCounts    map[string]int
}

func buildCoverageDebt(
	candidates []store.CoverageCandidate,
	results []ResultView,
	snapshot topology.Snapshot,
	options coverageDebtBuildOptions,
) coverageDebtBuildResult {
	now := options.now.UTC()
	if options.entityLimit <= 0 || options.entityLimit > maxCoverageDebtEntityLimit {
		options.entityLimit = defaultCoverageDebtEntityLimit
	}
	entities := buildCoverageDebtSites(candidates, results)
	siteCount := len(entities)
	topologyEntities, evidenceCounts := buildCoverageDebtTopology(snapshot)
	entities = append(entities, topologyEntities...)
	sort.Slice(entities, func(i, j int) bool {
		if entities[i].kind != entities[j].kind {
			if entities[i].kind == "site" {
				return true
			}
			if entities[j].kind == "site" {
				return false
			}
			return entities[i].kind < entities[j].kind
		}
		return entities[i].id < entities[j].id
	})

	entitiesTruncated := len(entities) > options.entityLimit
	topologyTruncated := len(topologyEntities) > max(options.entityLimit-siteCount, 0)
	if entitiesTruncated {
		entities = entities[:options.entityLimit]
	}

	items := make([]coverageDebtItem, 0, len(entities)*coverageDebtPlaneCount)
	for _, entity := range entities {
		for _, plane := range coverageDebtPlanes {
			evidence, exact := entity.evidence[plane]
			item := coverageDebtItem{
				EntityID: entity.id, EntityKind: entity.kind, Label: entity.label,
				Region: entity.region, Site: entity.site, Plane: plane,
				State: "unknown", StaleAfterSeconds: int(coverageDebtStaleAfter.Seconds()),
				EvidenceBasis: "no_exact_entity_correlation",
				NextAction: coverageDebtAction{
					Kind: "navigate", Label: "Inspect topology", Href: "/topology",
				},
			}
			if entity.kind == "site" {
				item.NextAction = coverageDebtAction{
					Kind: "navigate", Label: "Inspect tests", Href: "/targets",
				}
			}
			if plane == "synthetic" && entity.kind == "site" {
				switch {
				case !options.evidenceRunning:
					item.EvidenceBasis = "producer_unwired"
				case (options.candidatesTruncated || options.resultsTruncated) &&
					(!exact || evidence.at.IsZero()):
					if options.resultsTruncated {
						item.EvidenceBasis = "result_evidence_truncated"
					} else {
						item.EvidenceBasis = "candidate_scan_truncated"
					}
				case !exact || evidence.at.IsZero():
					item.State = "uncovered"
					item.EvidenceBasis = "no_persisted_test_result"
				default:
					applyCoverageDebtEvidence(&item, evidence, now)
				}
			} else if exact && evidence.expected {
				switch {
				case !options.topologyRunning:
					item.EvidenceBasis = "producer_unwired"
				case evidence.at.IsZero():
					item.State = "uncovered"
					item.EvidenceBasis = evidence.basis
					item.EvidenceRef = evidence.ref
				default:
					applyCoverageDebtEvidence(&item, evidence, now)
				}
			}
			items = append(items, item)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if coverageDebtStateRank(items[i].State) != coverageDebtStateRank(items[j].State) {
			return coverageDebtStateRank(items[i].State) < coverageDebtStateRank(items[j].State)
		}
		if items[i].EntityKind != items[j].EntityKind {
			return items[i].EntityKind < items[j].EntityKind
		}
		if items[i].EntityID != items[j].EntityID {
			return items[i].EntityID < items[j].EntityID
		}
		return items[i].Plane < items[j].Plane
	})
	evidenceCounts["synthetic"] = countCoverageDebtResults(results)
	return coverageDebtBuildResult{
		items: items, entitiesTruncated: entitiesTruncated,
		topologyTruncated: topologyTruncated, evidenceCounts: evidenceCounts,
	}
}

func applyCoverageDebtEvidence(item *coverageDebtItem, evidence coverageDebtEvidence, now time.Time) {
	staleAfter := evidence.staleAfter
	if staleAfter <= 0 {
		staleAfter = coverageDebtStaleAfter
	}
	at := evidence.at.UTC()
	age := max(int(now.Sub(at).Seconds()), 0)
	item.ObservedAt = &at
	item.EvidenceAgeSeconds = &age
	item.StaleAfterSeconds = int(staleAfter.Seconds())
	item.EvidenceBasis = evidence.basis
	item.EvidenceRef = evidence.ref
	switch {
	case at.After(now.Add(coverageDebtFutureSkew)):
		item.State = "unknown"
		item.EvidenceBasis = "future_evidence_timestamp"
	case at.Before(now.Add(-staleAfter)):
		item.State = "stale"
	default:
		item.State = "covered"
	}
}

func buildCoverageDebtSites(candidates []store.CoverageCandidate, results []ResultView) []coverageDebtEntity {
	seriesCounts := make(map[string]int, len(candidates))
	for _, candidate := range candidates {
		if candidate.AgentID == "" {
			continue
		}
		series := candidate.ProbeFamily + "\x00" + candidate.Target + "\x00" + candidate.AgentID
		seriesCounts[series]++
	}
	resultBySeries := make(map[string]ResultView, len(results))
	for _, result := range results {
		key := result.Attributes[otel.AttrTestID] + "\x00" + result.Type + "\x00" + result.Target + "\x00" + result.AgentID
		if prior, ok := resultBySeries[key]; !ok || result.ObservedAt.After(prior.ObservedAt) {
			resultBySeries[key] = result
		}
	}
	bySite := map[string]*coverageDebtEntity{}
	for _, candidate := range candidates {
		key := candidate.Region + "\x00" + candidate.Site
		entity, ok := bySite[key]
		if !ok {
			entity = &coverageDebtEntity{
				id: "site:" + candidate.Region + ":" + candidate.Site, kind: "site",
				label: candidate.Site, region: candidate.Region, site: candidate.Site,
				evidence: map[string]coverageDebtEvidence{
					"synthetic": {expected: true},
				},
			}
			bySite[key] = entity
		}
		if candidate.AgentID == "" {
			continue
		}
		series := candidate.ProbeFamily + "\x00" + candidate.Target + "\x00" + candidate.AgentID
		result, ok := resultBySeries[candidate.TestID+"\x00"+series]
		// Older producers did not stamp probectl.test.id. Their evidence is
		// unambiguous only while exactly one candidate owns the remaining
		// type/target/agent tuple. Duplicate definitions fail closed instead of
		// borrowing another test's observation.
		if !ok && seriesCounts[series] == 1 {
			result, ok = resultBySeries["\x00"+series]
		}
		if !ok {
			continue
		}
		staleAfter := time.Duration(max(candidate.IntervalSeconds*3, 300)) * time.Second
		current := entity.evidence["synthetic"]
		if current.at.IsZero() || result.ObservedAt.After(current.at) {
			entity.evidence["synthetic"] = coverageDebtEvidence{
				at: result.ObservedAt, staleAfter: staleAfter, basis: "latest_test_result",
				ref: candidate.TestID + "/" + candidate.AgentID, expected: true,
			}
		}
	}
	out := make([]coverageDebtEntity, 0, len(bySite))
	for _, entity := range bySite {
		out = append(out, *entity)
	}
	return out
}

func buildCoverageDebtTopology(snapshot topology.Snapshot) ([]coverageDebtEntity, map[string]int) {
	incident := make(map[string]map[string]topology.Edge)
	counts := map[string]int{"path": 0, "flow": 0, "routing": 0, "device": 0}
	for _, edge := range snapshot.Edges {
		plane := coverageDebtPlaneForEdge(edge.Kind)
		if plane == "" {
			continue
		}
		counts[plane]++
		for _, nodeID := range [...]string{edge.From, edge.To} {
			if incident[nodeID] == nil {
				incident[nodeID] = map[string]topology.Edge{}
			}
			if prior, ok := incident[nodeID][plane]; !ok || edge.LastSeen.After(prior.LastSeen) {
				incident[nodeID][plane] = edge
			}
		}
	}
	out := make([]coverageDebtEntity, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		entity := coverageDebtEntity{
			id: node.ID, kind: string(node.Kind), label: node.Label,
			evidence: map[string]coverageDebtEvidence{},
		}
		if node.Kind == topology.NodeDevice {
			// A device node is direct device-telemetry evidence: this node kind
			// can only be created by ObserveDevice. Generic node existence never
			// takes this path.
			entity.evidence["device"] = coverageDebtEvidence{
				at: node.LastSeen, staleAfter: coverageDebtStaleAfter,
				basis: "topology_device_node", ref: node.ID, expected: true,
			}
			counts["device"]++
		} else if plane := coverageDebtExpectedPlaneForNode(node.Kind); plane != "" {
			if edge, ok := incident[node.ID][plane]; ok {
				entity.evidence[plane] = coverageDebtEvidence{
					at: edge.LastSeen, staleAfter: coverageDebtStaleAfter,
					basis: "topology_" + plane + "_edge", ref: edge.ID, expected: true,
				}
			} else {
				// The typed node tells us which plane should link it, but does
				// not itself prove usable plane coverage.
				entity.evidence[plane] = coverageDebtEvidence{
					basis: "no_persisted_topology_edge", ref: node.ID, expected: true,
				}
			}
		} else if node.Kind == topology.NodeHop {
			for plane, edge := range incident[node.ID] {
				entity.evidence[plane] = coverageDebtEvidence{
					at: edge.LastSeen, staleAfter: coverageDebtStaleAfter,
					basis: "topology_" + plane + "_edge", ref: edge.ID, expected: true,
				}
			}
		}
		out = append(out, entity)
	}
	return out, counts
}

func coverageDebtExpectedPlaneForNode(kind topology.NodeKind) string {
	switch kind {
	case topology.NodeAgent, topology.NodeHost:
		return "path"
	case topology.NodeService:
		return "flow"
	case topology.NodePrefix, topology.NodeAS:
		return "routing"
	default:
		return ""
	}
}

func coverageDebtPlaneForEdge(kind topology.EdgeKind) string {
	switch kind {
	case topology.EdgePath:
		return "path"
	case topology.EdgeFlow:
		return "flow"
	case topology.EdgeRouting:
		return "routing"
	case topology.EdgeDevice:
		return "device"
	default:
		return ""
	}
}

func countCoverageDebtResults(results []ResultView) int {
	series := make(map[string]struct{}, len(results))
	for _, result := range results {
		series[result.Type+"\x00"+result.Target+"\x00"+result.AgentID] = struct{}{}
	}
	return len(series)
}

func coverageDebtStateRank(state string) int {
	switch state {
	case "uncovered":
		return 0
	case "stale":
		return 1
	case "unknown":
		return 2
	default:
		return 3
	}
}

func coverageDebtProducerRows(
	registrations store.CoverageProducerCounts,
	evidence map[string]int,
	evidenceRunning, topologyRunning bool,
) []coverageDebtProducer {
	registered := map[string]int{
		"synthetic": registrations.Synthetic,
		"path":      registrations.Path,
		"flow":      registrations.Flow,
		"routing":   registrations.Routing,
		"device":    registrations.Device,
	}
	out := make([]coverageDebtProducer, 0, len(coverageDebtPlanes))
	for _, plane := range coverageDebtPlanes {
		running := topologyRunning
		if plane == "synthetic" {
			running = evidenceRunning
		}
		status := "unregistered"
		switch {
		case !running:
			status = "unwired"
		case evidence[plane] > 0:
			status = "observed"
		case registered[plane] > 0:
			status = "idle"
		}
		out = append(out, coverageDebtProducer{
			Plane: plane, RegisteredCount: registered[plane],
			RuntimeRunning: running, EvidenceCount: evidence[plane], Status: status,
		})
	}
	return out
}

// handleCoverageDebt serves a bounded, read-only, tenant-local debt map. The
// route gate checks test.read; the explicit checks below are required because
// the contract also reads agent registration metadata and topology evidence.
func (s *Server) handleCoverageDebt(w http.ResponseWriter, r *http.Request) error {
	principal := auth.PrincipalFrom(r.Context())
	if principal == nil || !principal.Permissions[permAgentRead] {
		return apierror.Forbidden("missing permission: " + permAgentRead)
	}
	if !principal.Permissions[ai.PermTopologyRead] {
		return apierror.Forbidden("missing permission: " + ai.PermTopologyRead)
	}
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	entityLimit := intQuery(r, "limit", defaultCoverageDebtEntityLimit)
	if entityLimit <= 0 || entityLimit > maxCoverageDebtEntityLimit {
		entityLimit = defaultCoverageDebtEntityLimit
	}

	var (
		candidates    []store.CoverageCandidate
		registrations store.CoverageProducerCounts
	)
	if err := s.inTenant(r, func(ctx context.Context, scope tenancy.Scope) error {
		rows, queryErr := (store.Agents{}).CoverageCandidates(
			ctx, scope, store.DefaultCoverageCandidateLimit+1,
		)
		if queryErr != nil {
			return queryErr
		}
		candidates = rows
		counts, queryErr := (store.Agents{}).CoverageProducers(ctx, scope)
		registrations = counts
		return queryErr
	}); err != nil {
		return err
	}
	candidatesTruncated := len(candidates) > store.DefaultCoverageCandidateLimit
	if candidatesTruncated {
		candidates = candidates[:store.DefaultCoverageCandidateLimit]
	}

	results := []ResultView{}
	resultsTruncated := false
	evidenceRunning := s.latestResults != nil
	if evidenceRunning {
		results, resultsTruncated = s.latestResults.ListWithTruncation(tenantID)
	}
	snapshot := topology.Snapshot{Tenant: tenantID}
	topologyRunning := s.topo != nil
	if topologyRunning {
		bound, bindErr := s.topo.ForTenant(tenantID)
		if bindErr != nil {
			return apierror.Forbidden("tenant topology scope is invalid").Wrap(bindErr)
		}
		snapshot = bound.Latest()
	}

	now := time.Now().UTC()
	built := buildCoverageDebt(candidates, results, snapshot, coverageDebtBuildOptions{
		now: now, evidenceRunning: evidenceRunning, topologyRunning: topologyRunning,
		candidatesTruncated: candidatesTruncated, resultsTruncated: resultsTruncated,
		entityLimit: entityLimit,
	})
	partial := make([]string, 0, 5)
	if !evidenceRunning {
		partial = append(partial, "synthetic evidence consumer is not wired")
	}
	if !topologyRunning {
		partial = append(partial, "topology evidence store is not wired")
	}
	if candidatesTruncated {
		partial = append(partial, "agent-test candidate scan reached its safety bound")
	}
	if resultsTruncated {
		partial = append(partial, "latest-result evidence reached its safety bound")
	}
	if built.entitiesTruncated {
		partial = append(partial, "entity scan reached its safety bound")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": built.items, "producers": coverageDebtProducerRows(
			registrations, built.evidenceCounts, evidenceRunning, topologyRunning,
		),
		"as_of": now, "stale_after_seconds": int(coverageDebtStaleAfter.Seconds()),
		"entity_limit": entityLimit, "candidate_limit": store.DefaultCoverageCandidateLimit,
		"candidates_truncated": candidatesTruncated,
		"results_truncated":    resultsTruncated,
		"entities_truncated":   built.entitiesTruncated,
		"topology_truncated":   built.topologyTruncated,
		"partial_reasons":      partial,
	})
	return nil
}
