// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

const (
	// DefaultCoverageCandidateLimit bounds the agent×test rows considered by
	// one coverage snapshot. The handler asks for one extra row to report
	// truncation honestly.
	DefaultCoverageCandidateLimit = 5000
	maxCoverageCandidateLimit     = DefaultCoverageCandidateLimit + 1
)

// CoverageCandidate is one enabled test joined to one locally owned vantage
// that can execute its probe family. AgentID is empty when no compatible
// vantage exists, preserving the uncovered test as an explicit row.
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
}

// CoverageCandidates performs the only relational join behind the owned-
// vantage cockpit. Both sides carry explicit tenant predicates in addition to
// forced RLS. That makes the tenant boundary visible in the query itself and
// prevents a future policy/configuration mistake from turning this into a
// cross-tenant agent×test product.
func (Agents) CoverageCandidates(ctx context.Context, s tenancy.Scope, limit int) ([]CoverageCandidate, error) {
	if limit <= 0 || limit > maxCoverageCandidateLimit {
		limit = maxCoverageCandidateLimit
	}
	rows, err := s.Q.Query(ctx, `
		SELECT t.id::text, t.name, t.type, t.target, t.interval_seconds,
		       COALESCE(a.id::text, ''),
		       COALESCE(NULLIF(a.labels->>'region', ''), 'unlabeled') AS region,
		       COALESCE(NULLIF(a.labels->>'site', ''), 'unlabeled') AS site,
		       COALESCE(a.status, 'unavailable'),
		       a.last_seen_at
		  FROM tests t
		  LEFT JOIN agents a
		    ON a.tenant_id = t.tenant_id
		   AND a.tenant_id = $1::uuid
		   AND (
		        jsonb_array_length(a.capabilities) = 0
		        OR a.capabilities ? t.type
		   )
		 WHERE t.tenant_id = $1::uuid
		   AND t.enabled = true
		 ORDER BY t.id, region, site, a.id
		 LIMIT $2`, s.Tenant.String(), limit)
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
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
