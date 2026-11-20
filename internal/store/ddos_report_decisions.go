// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DDoSReportDecisions reads this tenant's decisions for a single report.
// Older routing proposals identify the incident through the cited receipt.
func DDoSReportDecisions(ctx context.Context, sc tenancy.Scope, incidentID, ruleID, fingerprint string) ([]alert.DDoSReportDecision, error) {
	const limit = 100
	rows, err := sc.Q.Query(ctx, `
		SELECT id::text, kind, state, created_at, decided_at
		FROM remediation_proposals
		WHERE tenant_id=$1 AND kind IN ('rtbh_review','flowspec_review')
		  AND (incident_id=$2 OR (
		       incident_id='' AND
		       COALESCE(rtbh_review,flowspec_review) #>> '{request,preview,rule_id}'=$3 AND
		       COALESCE(rtbh_review,flowspec_review) #>> '{request,preview,receipt_fingerprint}'=$4
		  ))
		ORDER BY created_at,id LIMIT $5`, sc.Tenant.String(), incidentID, ruleID, fingerprint, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]alert.DDoSReportDecision, 0, 4)
	for rows.Next() {
		if len(out) == limit {
			return nil, alert.ErrQueryGroups
		}
		var decision alert.DDoSReportDecision
		if err := rows.Scan(&decision.ProposalID, &decision.Kind, &decision.State, &decision.CreatedAt, &decision.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, decision)
	}
	return out, rows.Err()
}
