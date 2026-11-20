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
func DDoSReportDecisions(ctx context.Context, sc tenancy.Scope, incidentID, ruleID, fingerprint, contextID string) ([]alert.DDoSReportDecision, error) {
	const limit = 100
	rows, err := sc.Q.Query(ctx, `
		SELECT own.id::text,
		       CASE WHEN own.kind='diversion_preview' THEN 'diversion_preview_' || (own.diversion_review #>> '{review,candidate,action}')
		            ELSE own.kind END,
		       own.state, own.created_at, own.decided_at
		FROM remediation_proposals own
		LEFT JOIN remediation_proposals original
		  ON original.tenant_id=$1 AND original.tenant_id=own.tenant_id AND original.kind='diversion_preview'
		 AND own.kind='diversion_preview' AND own.diversion_review #>> '{review,candidate,action}'='stop'
		 AND original.id::text=own.diversion_review #>> '{review,candidate,start_preview_id}'
		WHERE own.tenant_id=$1 AND own.kind IN ('rtbh_review','flowspec_review','diversion_preview')
		  AND ($6='' OR CASE WHEN own.kind='diversion_preview' THEN
		      COALESCE(own.diversion_review #>> '{selection,observation,context_id}', original.diversion_review #>> '{selection,observation,context_id}')
		      ELSE COALESCE(own.rtbh_review,own.flowspec_review) #>> '{request,preview,context_id}' END=$6)
		  AND (own.incident_id=$2 OR (
		       own.incident_id='' AND
		       CASE WHEN own.kind='diversion_preview' THEN
		           COALESCE(own.diversion_review #>> '{selection,observation,rule_id}', original.diversion_review #>> '{selection,observation,rule_id}')=$3 AND
		           COALESCE(own.diversion_review #>> '{selection,observation,receipt_fingerprint}', original.diversion_review #>> '{selection,observation,receipt_fingerprint}')=$4
		       ELSE
		           COALESCE(own.rtbh_review,own.flowspec_review) #>> '{request,preview,rule_id}'=$3 AND
		           COALESCE(own.rtbh_review,own.flowspec_review) #>> '{request,preview,receipt_fingerprint}'=$4
		       END
		  ))
		ORDER BY own.created_at,own.id LIMIT $5`, sc.Tenant.String(), incidentID, ruleID, fingerprint, limit+1, contextID)
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
