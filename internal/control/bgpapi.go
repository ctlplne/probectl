// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const (
	bgpEventsDefaultLimit = 100
	bgpEventsMaxLimit     = 200
)

type bgpEventItem struct {
	ID         string            `json:"id"`
	IncidentID string            `json:"incident_id"`
	Kind       string            `json:"kind"`
	Severity   incident.Severity `json:"severity"`
	Title      string            `json:"title"`
	Summary    string            `json:"summary,omitempty"`
	Target     string            `json:"target,omitempty"`
	Prefix     string            `json:"prefix,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// handleListBGPEvents serves GET /v1/bgp/events — the tenant's durable BGP
// routing event read model. The data source is incident_signals because the BGP
// consumer already normalizes bus events into the cross-plane incident timeline.
func (s *Server) handleListBGPEvents(w http.ResponseWriter, r *http.Request) error {
	limit, err := intParam(r, "limit", bgpEventsDefaultLimit)
	if err != nil {
		return err
	}
	if limit > bgpEventsMaxLimit {
		limit = bgpEventsMaxLimit
	}
	if s.pool == nil {
		if _, err := s.principalTenant(r); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items":           []bgpEventItem{},
			"bgp_running":     false,
			"effective_limit": limit,
		})
		return nil
	}

	prefix := strings.TrimSpace(r.URL.Query().Get("prefix"))
	asn := normalizeASNFilter(r.URL.Query().Get("asn"))
	var items []bgpEventItem
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		items, e = listBGPEventItems(ctx, sc, prefix, asn, limit)
		return e
	}); err != nil {
		return err
	}
	if items == nil {
		items = []bgpEventItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":           items,
		"bgp_running":     true,
		"effective_limit": limit,
	})
	return nil
}

func normalizeASNFilter(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(strings.ToUpper(raw), "AS")
	return strings.TrimSpace(raw)
}

func listBGPEventItems(ctx context.Context, sc tenancy.Scope, prefix, asn string, limit int) ([]bgpEventItem, error) {
	rows, err := sc.Q.Query(ctx,
		`SELECT incident_id::text, kind, severity, title, summary, target, prefix, attributes, occurred_at
		   FROM incident_signals
		  WHERE plane = 'bgp'
		    AND ($1 = '' OR prefix = $1 OR target = $1)
		    AND ($2 = '' OR attributes->>'new_origin_asn' = $2
		              OR attributes->>'old_origin_asn' = $2
		              OR attributes->>'origin_asn' = $2
		              OR attributes->>'peer_asn' = $2)
		  ORDER BY occurred_at DESC
		  LIMIT $3`, prefix, asn, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []bgpEventItem{}
	for rows.Next() {
		var item bgpEventItem
		var severity string
		var attrs []byte
		if err := rows.Scan(&item.IncidentID, &item.Kind, &severity, &item.Title,
			&item.Summary, &item.Target, &item.Prefix, &attrs, &item.OccurredAt); err != nil {
			return nil, err
		}
		item.ID = item.IncidentID
		item.Severity = incident.Severity(severity)
		if len(attrs) > 0 {
			item.Attributes = map[string]string{}
			if err := json.Unmarshal(attrs, &item.Attributes); err != nil {
				return nil, err
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
