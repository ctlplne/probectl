// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PendingReportEmail is routing metadata, never source facts or report bytes.
type PendingReportEmail struct {
	ID, ScheduleID, OwnerID, DestinationID, CurrentDestinationID string
	Attempts                                                     int64
	ProspectRevision                                             *int64
}

func (DashboardReports) QueueReportEmail(ctx context.Context, sc tenancy.Scope, id, destination string) error {
	_, err := sc.Q.Exec(ctx, `UPDATE dashboard_report_artifacts SET email_destination_id=$3,email_state='pending',email_next_attempt_at=transaction_timestamp() WHERE tenant_id=$1 AND id=$2 AND email_destination_id IS NULL`, sc.Tenant.String(), id, destination)
	return err
}
func (DashboardReports) PendingReportEmails(ctx context.Context, sc tenancy.Scope, now time.Time, limit int) ([]PendingReportEmail, error) {
	rows, err := sc.Q.Query(ctx, `WITH due AS (
		SELECT a.id,s.id AS schedule_id,s.owner_id,a.email_destination_id,s.destination_id AS current_destination_id,
		 a.email_attempts,NULL::bigint AS prospect_revision,a.email_next_attempt_at
		FROM dashboard_report_artifacts a
		JOIN dashboard_report_schedules s ON (s.tenant_id,s.id)=(a.tenant_id,a.schedule_id)
		WHERE a.tenant_id=$1 AND s.tenant_id=$1 AND s.enabled AND a.email_state='pending' AND a.email_next_attempt_at<=$2
		UNION ALL
		SELECT a.id,'',p.owner_id::text,a.email_destination_id,p.consent_destination_id,a.email_attempts,p.revision,a.email_next_attempt_at
		FROM prospect_engagements p
		JOIN dashboard_report_artifacts a ON (a.tenant_id,a.id)=(p.tenant_id,p.assessment_artifact_id)
		WHERE p.tenant_id=$1 AND a.tenant_id=$1 AND a.schedule_id IS NULL AND p.ends_at<=$2
		 AND p.converted_at IS NULL AND p.consented_at IS NOT NULL AND p.consent_revoked_at IS NULL AND p.consent_revision=p.revision
		 AND a.email_destination_id=p.consent_destination_id AND a.email_state='pending' AND a.email_next_attempt_at<=$2
	)
	SELECT id,schedule_id,owner_id,email_destination_id,current_destination_id,email_attempts,prospect_revision
	FROM due ORDER BY email_next_attempt_at,id LIMIT $3`, sc.Tenant.String(), now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []PendingReportEmail
	for rows.Next() {
		var item PendingReportEmail
		if err := rows.Scan(&item.ID, &item.ScheduleID, &item.OwnerID, &item.DestinationID, &item.CurrentDestinationID, &item.Attempts, &item.ProspectRevision); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
func (DashboardReports) MarkReportEmailAttempt(ctx context.Context, sc tenancy.Scope, id string, now, next time.Time) (bool, error) {
	tag, err := sc.Q.Exec(ctx, `UPDATE dashboard_report_artifacts SET email_attempts=email_attempts+1,email_next_attempt_at=$3 WHERE tenant_id=$1 AND id=$2 AND email_state='pending' AND email_next_attempt_at<=$4`, sc.Tenant.String(), id, next, now)
	return err == nil && tag.RowsAffected() == 1, err
}
func (DashboardReports) CompleteReportEmail(ctx context.Context, sc tenancy.Scope, id, state string, now time.Time) error {
	_, err := sc.Q.Exec(ctx, `UPDATE dashboard_report_artifacts SET email_state=$3,email_next_attempt_at=NULL,email_delivered_at=CASE WHEN $3='sent' THEN $4::timestamptz ELSE NULL END WHERE tenant_id=$1 AND id=$2 AND email_state='pending'`, sc.Tenant.String(), id, state, now)
	return err
}

// SetReportScheduleDestination changes only an owned schedule. Authority and
// the configured tenant recipient binding are checked by the caller's audited
// transaction; changing the destination withdraws pending old deliveries.
func (DashboardReports) SetReportScheduleDestination(ctx context.Context, sc tenancy.Scope, id, owner, destination string) error {
	tag, err := sc.Q.Exec(ctx, `UPDATE dashboard_report_schedules SET destination_id=$4,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 AND owner_id=$3`, sc.Tenant.String(), id, owner, destination)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return apierror.NotFound("report schedule not found")
	}
	_, err = sc.Q.Exec(ctx, `UPDATE dashboard_report_artifacts SET email_state='withdrawn',email_next_attempt_at=NULL WHERE tenant_id=$1 AND schedule_id=$2 AND email_state='pending' AND email_destination_id<>$3`, sc.Tenant.String(), id, destination)
	return err
}
