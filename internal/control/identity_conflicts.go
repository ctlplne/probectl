// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/topology"
)

const (
	identityConflictDefaultLimit = 100
	identityConflictMaxLimit     = 200
	identityConflictStaleAfter   = time.Hour
	identityConflictFutureSkew   = 5 * time.Minute
)

type identityConflictClaimView struct {
	Value      string    `json:"value"`
	Source     string    `json:"source"`
	AgentID    string    `json:"agent_id,omitempty"`
	Basis      string    `json:"basis"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	AgeSeconds int64     `json:"age_seconds"`
	Freshness  string    `json:"freshness"`
}

type identityAffectedCorrelation struct {
	Plane  string `json:"plane"`
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
	Href   string `json:"href"`
}

type identityReviewProposal struct {
	Mode           string `json:"mode"`
	Instruction    string `json:"instruction"`
	MergeSupported bool   `json:"merge_supported"`
}

type identityConflictView struct {
	ID                   string                        `json:"id"`
	Kind                 topology.IdentityConflictKind `json:"kind"`
	Subject              string                        `json:"subject"`
	Status               string                        `json:"status"`
	Confidence           string                        `json:"confidence"`
	Basis                string                        `json:"basis"`
	FirstSeen            time.Time                     `json:"first_seen"`
	LastSeen             time.Time                     `json:"last_seen"`
	Claims               []identityConflictClaimView   `json:"claims"`
	AffectedCorrelations []identityAffectedCorrelation `json:"affected_correlations"`
	ReviewProposal       identityReviewProposal        `json:"review_proposal"`
}

type identityConflictFilter struct {
	Query  string
	Kind   string
	Source string
	Status string
}

// handleIdentityConflicts serves the bounded, replayable identity-conflict
// read model. Tenant binding happens before the store accepts the query.
func (s *Server) handleIdentityConflicts(w http.ResponseWriter, r *http.Request) error {
	tenantID, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	limit, err := intParam(r, "limit", identityConflictDefaultLimit)
	if err != nil {
		return err
	}
	if limit > identityConflictMaxLimit {
		limit = identityConflictMaxLimit
	}
	filter := identityConflictFilter{
		Query:  strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q"))),
		Kind:   strings.TrimSpace(r.URL.Query().Get("kind")),
		Source: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source"))),
		Status: strings.TrimSpace(r.URL.Query().Get("status")),
	}
	if !validIdentityConflictKind(filter.Kind) {
		return apierror.BadRequest("kind must be one of management_address, device_name, interface_address, interface_name, interface_index")
	}
	if filter.Status != "" && filter.Status != "active" && filter.Status != "stale" && filter.Status != "unknown" {
		return apierror.BadRequest("status must be one of active, stale, unknown")
	}
	if s.topo == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"items": []identityConflictView{}, "topology_running": false,
			"effective_limit": limit, "truncated": false,
			"partial_reasons": []string{"topology identity store is not wired"},
		})
		return nil
	}
	bound, err := s.topo.ForTenant(tenantID)
	if err != nil {
		return apierror.Forbidden("tenant topology scope is invalid").Wrap(err)
	}
	snapshot := bound.IdentityConflicts()
	now := time.Now().UTC()
	items := buildIdentityConflictViews(snapshot.Items, now)
	items = filterIdentityConflictViews(items, filter)
	filteredCount := len(items)
	responseTruncated := filteredCount > limit
	if responseTruncated {
		items = items[:limit]
	}
	partial := []string{}
	if snapshot.Truncated {
		partial = append(partial, "tenant identity claim store reached its safety bound")
	}
	if responseTruncated {
		partial = append(partial, "filtered conflict response reached its safety bound")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "topology_running": true, "as_of": now,
		"stale_after_seconds": int(identityConflictStaleAfter.Seconds()),
		"effective_limit":     limit, "filtered_count": filteredCount,
		"store_truncated": snapshot.Truncated, "response_truncated": responseTruncated,
		"truncated":       snapshot.Truncated || responseTruncated,
		"partial_reasons": partial,
	})
	return nil
}

func validIdentityConflictKind(kind string) bool {
	switch topology.IdentityConflictKind(kind) {
	case "", topology.IdentityManagementAddress, topology.IdentityDeviceName,
		topology.IdentityInterfaceAddress, topology.IdentityInterfaceName,
		topology.IdentityInterfaceIndex:
		return true
	default:
		return false
	}
}

func buildIdentityConflictViews(
	conflicts []topology.IdentityConflict,
	now time.Time,
) []identityConflictView {
	out := make([]identityConflictView, 0, len(conflicts))
	for _, conflict := range conflicts {
		item := identityConflictView{
			ID: conflict.ID, Kind: conflict.Kind, Subject: conflict.Subject,
			Basis:     "distinct_values_for_one_tenant_local_identity_key",
			FirstSeen: conflict.FirstSeen, LastSeen: conflict.LastSeen,
			AffectedCorrelations: affectedIdentityCorrelations(conflict),
			ReviewProposal: identityReviewProposal{
				Mode:           "read_only",
				Instruction:    "Compare source ownership and freshness, then correct the authoritative producer outside probectl.",
				MergeSupported: false,
			},
		}
		freshValues := map[string]struct{}{}
		freshSources := map[string]struct{}{}
		hasFuture := false
		for _, claim := range conflict.Claims {
			age := now.Sub(claim.LastSeen)
			freshness := "fresh"
			switch {
			case claim.LastSeen.After(now.Add(identityConflictFutureSkew)):
				freshness = "future"
				hasFuture = true
			case age > identityConflictStaleAfter:
				freshness = "stale"
			default:
				freshValues[strings.ToLower(claim.Value)] = struct{}{}
				freshSources[strings.ToLower(claim.Source)] = struct{}{}
			}
			if age < 0 {
				age = 0
			}
			item.Claims = append(item.Claims, identityConflictClaimView{
				Value: claim.Value, Source: claim.Source, AgentID: claim.AgentID, Basis: claim.Basis,
				FirstSeen: claim.FirstSeen, LastSeen: claim.LastSeen,
				AgeSeconds: int64(age / time.Second), Freshness: freshness,
			})
		}
		switch {
		case hasFuture:
			item.Status, item.Confidence = "unknown", "low"
		case len(freshValues) >= 2 && len(freshSources) >= 2:
			item.Status, item.Confidence = "active", "high"
		case len(freshValues) >= 2:
			item.Status, item.Confidence = "active", "medium"
		default:
			item.Status, item.Confidence = "stale", "low"
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		rank := func(state string) int {
			switch state {
			case "active":
				return 0
			case "unknown":
				return 1
			default:
				return 2
			}
		}
		if rank(out[i].Status) != rank(out[j].Status) {
			return rank(out[i].Status) < rank(out[j].Status)
		}
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func filterIdentityConflictViews(
	items []identityConflictView,
	filter identityConflictFilter,
) []identityConflictView {
	out := make([]identityConflictView, 0, len(items))
	for _, item := range items {
		if filter.Kind != "" && string(item.Kind) != filter.Kind {
			continue
		}
		if filter.Status != "" && item.Status != filter.Status {
			continue
		}
		if filter.Source != "" {
			matched := false
			for _, claim := range item.Claims {
				if strings.EqualFold(claim.Source, filter.Source) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if filter.Query != "" {
			haystack := []string{item.ID, string(item.Kind), item.Subject}
			for _, claim := range item.Claims {
				haystack = append(haystack, claim.Value, claim.Source, claim.AgentID, claim.Basis)
			}
			if !strings.Contains(strings.ToLower(strings.Join(haystack, " ")), filter.Query) {
				continue
			}
		}
		out = append(out, item)
	}
	return out
}

func affectedIdentityCorrelations(conflict topology.IdentityConflict) []identityAffectedCorrelation {
	type candidate struct {
		plane, kind, ref, reason string
	}
	candidates := []candidate{}
	topologySearch := func(value string) string {
		return "/topology?topo_q=" + url.QueryEscape(value)
	}
	switch conflict.Kind {
	case topology.IdentityDeviceName:
		candidates = append(candidates,
			candidate{"topology", "device_node", "device:" + conflict.Subject, "Device label attribution may name the wrong node."},
			candidate{"flow", "exporter", conflict.Subject, "Exporter attribution may inherit the wrong device name."},
		)
	case topology.IdentityManagementAddress:
		for _, claim := range conflict.Claims {
			candidates = append(candidates,
				candidate{"topology", "device_node", "device:" + claim.Value, "One device name points at competing management addresses."},
				candidate{"flow", "exporter", claim.Value, "Exporter-to-device attribution may select the wrong address."},
			)
		}
	case topology.IdentityInterfaceAddress:
		candidates = append(candidates,
			candidate{"path", "hop", "hop:" + conflict.Subject, "Path-hop ownership is disputed by device telemetry."},
			candidate{"topology", "device_edge", "hop:" + conflict.Subject, "Device-to-hop topology linkage may be ambiguous."},
		)
	case topology.IdentityInterfaceName, topology.IdentityInterfaceIndex:
		address := conflict.Subject
		if before, _, found := strings.Cut(address, "@"); found {
			address = before
		}
		candidates = append(candidates,
			candidate{"flow", "exporter_interface", conflict.Subject, "Flow interface attribution may use the wrong index/name pair."},
			candidate{"topology", "device_node", "device:" + address, "Topology evidence is attached to a device with disputed interface identity."},
		)
	}
	seen := map[string]bool{}
	out := make([]identityAffectedCorrelation, 0, len(candidates))
	for _, item := range candidates {
		key := item.plane + "\x00" + item.kind + "\x00" + item.ref
		if seen[key] || len(out) >= 8 {
			continue
		}
		seen[key] = true
		out = append(out, identityAffectedCorrelation{
			Plane: item.plane, Kind: item.kind, Ref: item.ref, Reason: item.reason,
			Href: topologySearch(strings.TrimPrefix(item.ref, "device:")),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].Plane + "\x00" + out[i].Kind + "\x00" + out[i].Ref
		right := out[j].Plane + "\x00" + out[j].Kind + "\x00" + out[j].Ref
		return left < right
	})
	return out
}
