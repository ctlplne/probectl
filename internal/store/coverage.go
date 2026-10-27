// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	// DefaultCoverageCandidateLimit bounds the agent×test rows considered by
	// one coverage snapshot. The handler asks for one extra row to report
	// truncation honestly.
	DefaultCoverageCandidateLimit = 5000
	maxCoverageCandidateLimit     = DefaultCoverageCandidateLimit + 1
)

// CoverageCandidate is one enabled test joined to one locally owned vantage
// that can execute its probe family or has exact matching execution evidence.
// EvidenceOnly distinguishes the latter. AgentID is empty when neither exists,
// preserving the uncovered test as an explicit row.
type CoverageCandidate struct {
	TestID          string
	TestName        string
	ProbeFamily     string
	Target          string
	IntervalSeconds int
	AgentID         string
	Region          string
	Site            string
	AgentStatus     string
	LastSeenAt      *time.Time
	// EvidenceOnly preserves past execution without claiming current capability.
	EvidenceOnly bool
}

// CoverageEvidence identifies an exact observed test/agent pair. The query
// still requires both records to belong to the caller tenant and the current
// definition to match the observed probe family and target.
type CoverageEvidence struct {
	TestID      string `json:"test_id"`
	AgentID     string `json:"agent_id"`
	ProbeFamily string `json:"probe_family"`
	Target      string `json:"target"`
}

// CoverageProducerCounts is a tenant-local count of registrations that can
// sustain each signal plane. Registration is readiness metadata only: callers
// must never turn it into covered/green without persisted evidence.
type CoverageProducerCounts struct {
	Synthetic int
	Path      int
	Flow      int
	Routing   int
	Device    int
}

// CoverageProducers counts only the caller tenant's locally registered agents
// and collectors. The explicit tenant predicate is defense in depth beside
// forced RLS. It performs no inventory discovery, geolocation, or outbound
// lookup.
func (Agents) CoverageProducers(ctx context.Context, s tenancy.Scope) (CoverageProducerCounts, error) {
	var out CoverageProducerCounts
	err := s.Q.QueryRow(ctx, `
		SELECT
			count(*) FILTER (
				WHERE NOT (capabilities ? 'collector')
				  AND (
					jsonb_array_length(capabilities) = 0
					OR capabilities ?| ARRAY['icmp', 'tcp', 'udp', 'http', 'dns', 'browser', 'voice']
				  )
			) AS synthetic,
			count(*) FILTER (
				WHERE NOT (capabilities ? 'collector')
				  AND (
					jsonb_array_length(capabilities) = 0
					OR capabilities ?| ARRAY['icmp', 'tcp', 'udp', 'http', 'dns']
				  )
			) AS path,
			count(*) FILTER (
				WHERE capabilities ? 'collector'
				  AND capabilities ?| ARRAY['flow', 'ebpf']
			) AS flow,
			count(*) FILTER (
				WHERE capabilities ? 'collector'
				  AND capabilities ? 'bgp'
			) AS routing,
			count(*) FILTER (
				WHERE capabilities ? 'collector'
				  AND capabilities ? 'device'
			) AS device
		  FROM agents
		 WHERE tenant_id = $1::uuid`, s.Tenant.String()).Scan(
		&out.Synthetic,
		&out.Path,
		&out.Flow,
		&out.Routing,
		&out.Device,
	)
	return out, err
}

// CoverageCandidates performs the only relational join behind the owned-
// vantage cockpit. Both sides carry explicit tenant predicates in addition to
// forced RLS. That makes the tenant boundary visible in the query itself and
// prevents a future policy/configuration mistake from turning this into a
// cross-tenant agent×test product.
func (Agents) CoverageCandidates(ctx context.Context, s tenancy.Scope, limit int, evidence ...CoverageEvidence) ([]CoverageCandidate, error) {
	if limit <= 0 || limit > maxCoverageCandidateLimit {
		limit = maxCoverageCandidateLimit
	}
	if evidence == nil {
		evidence = []CoverageEvidence{}
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return nil, err
	}
	rows, err := s.Q.Query(ctx, `
		SELECT t.id::text, t.name, t.type, t.target, t.interval_seconds,
		       COALESCE(a.id::text, ''),
		       COALESCE(NULLIF(a.labels->>'region', ''), 'unlabeled') AS region,
		       COALESCE(NULLIF(a.labels->>'site', ''), 'unlabeled') AS site,
		       COALESCE(a.status, 'unavailable'),
		       a.last_seen_at,
         COALESCE(NOT (jsonb_array_length(a.capabilities) = 0 OR a.capabilities ? t.type), false)
		  FROM tests t
		  LEFT JOIN agents a
		    ON a.tenant_id = t.tenant_id
		   AND a.tenant_id = $1::uuid
		   AND (
		        jsonb_array_length(a.capabilities) = 0
		        OR a.capabilities ? t.type
            OR EXISTS (
              SELECT 1 FROM jsonb_to_recordset($3::jsonb)
                AS e(test_id text, agent_id text, probe_family text, target text)
              WHERE e.test_id = t.id::text AND e.agent_id = a.id::text
                AND e.probe_family = t.type AND e.target = t.target
            )
		   )
		 WHERE t.tenant_id = $1::uuid
		   AND t.enabled = true
		 ORDER BY t.id, region, site, a.id
		 LIMIT $2`, s.Tenant.String(), limit, evidenceJSON)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]CoverageCandidate, 0)
	for rows.Next() {
		var row CoverageCandidate
		if err := rows.Scan(
			&row.TestID,
			&row.TestName,
			&row.ProbeFamily,
			&row.Target,
			&row.IntervalSeconds,
			&row.AgentID,
			&row.Region,
			&row.Site,
			&row.AgentStatus,
			&row.LastSeenAt,
			&row.EvidenceOnly,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
