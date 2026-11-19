// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// ProspectErasureEvidence links retained consent to the exact archived PDF.
// It carries no report bytes or recipient addresses and does not grant authority.
type ProspectErasureEvidence struct {
	ArtifactID            string
	DestinationID         string
	BodySHA256            string
	BodyBytes             int64
	DeliveredAt           time.Time
	ConsentAuditSequence  int64
	ConsentAuditHash      string
	DeliveryAuditSequence int64
	DeliveryAuditHash     string
}

// ErasureEvidence looks for both eligible receipts within the bound tenant.
// The caller still has to verify the report bytes and revalidate current
// authority, source evidence and destination before any lifecycle transition.
func (ProspectEngagements) ErasureEvidence(ctx context.Context, sc tenancy.Scope, engagement ProspectEngagement, deliveryActor string) (*ProspectErasureEvidence, error) {
	if err := prospectScope(ctx, sc); err != nil {
		return nil, err
	}
	if !engagement.HasCurrentDeliveryConsent() || engagement.AssessmentArtifactID == "" || deliveryActor == "" {
		return nil, nil
	}
	var out ProspectErasureEvidence
	err := sc.Q.QueryRow(ctx, `SELECT a.id,a.email_destination_id,encode(a.body_digest,'hex'),a.body_bytes,a.email_delivered_at,
		consent.seq,consent.hash,delivery.seq,delivery.hash
	FROM prospect_engagements p
	JOIN dashboard_report_artifacts a ON (a.tenant_id,a.id)=(p.tenant_id,p.assessment_artifact_id)
	JOIN LATERAL (
		SELECT e.seq,e.hash FROM audit_events e
		WHERE e.tenant_id=p.tenant_id AND e.action='lifecycle.prospect_created' AND e.target=p.tenant_id::text
		 AND e.created_at>=p.starts_at AND e.created_at<=p.ends_at AND e.data_canonical IS NOT NULL
		 AND e.data->>'outcome'='success' AND e.data->>'owner_id'=p.owner_id::text AND e.data->>'tenant_slug'=p.tenant_slug
		 AND e.data->>'revision'=p.revision::text AND e.data->>'consent_revision'=p.consent_revision::text
		 AND e.data->>'assessment_view_id'=p.assessment_view_id AND e.data->>'destination_id'=p.consent_destination_id
		 AND (e.data->>'assessment_view_revision')::timestamptz=p.assessment_view_revision
		 AND (e.data->>'starts_at')::timestamptz=p.starts_at AND (e.data->>'ends_at')::timestamptz=p.ends_at
		ORDER BY e.seq DESC LIMIT 1
	) consent ON true
	JOIN LATERAL (
		SELECT e.seq,e.hash FROM audit_events e
		WHERE e.tenant_id=p.tenant_id AND e.action='dashboard.report_email_sent' AND e.target=a.id AND e.actor=$5
		 AND e.seq>consent.seq AND e.created_at>=a.email_delivered_at AND e.data_canonical IS NOT NULL
		 AND e.data->>'prospect_revision'=p.revision::text AND e.data->>'destination_id'=a.email_destination_id
		 AND e.data->>'body_sha256'=encode(a.body_digest,'hex') AND e.data->>'body_bytes'=a.body_bytes::text
		ORDER BY e.seq DESC LIMIT 1
	) delivery ON true
	WHERE p.tenant_id=$1 AND a.tenant_id=$1 AND p.revision=$2 AND p.owner_id=$3 AND a.id=$4
	 AND p.consent_destination_id=$6 AND p.tenant_slug=$7 AND p.assessment_view_revision=$8
	 AND p.ends_at<=clock_timestamp() AND p.converted_at IS NULL AND p.consent_revoked_at IS NULL
	 AND p.consented_at IS NOT NULL AND p.consent_revision=p.revision AND p.consent_destination_id=a.email_destination_id
	 AND a.schedule_id IS NULL AND a.dashboard_id=p.assessment_view_id AND a.format='pdf'
	 AND a.absolute_from=p.starts_at AND a.absolute_to=p.ends_at
	 AND a.body_storage='chunks' AND a.body_bytes>0 AND octet_length(a.body_digest)=32
	 AND a.email_state='sent' AND a.email_delivered_at>=p.ends_at`,
		sc.Tenant.String(), engagement.Revision, engagement.OwnerID, engagement.AssessmentArtifactID, deliveryActor,
		engagement.DestinationID, engagement.TenantSlug, engagement.AssessmentAt).
		Scan(&out.ArtifactID, &out.DestinationID, &out.BodySHA256, &out.BodyBytes, &out.DeliveredAt,
			&out.ConsentAuditSequence, &out.ConsentAuditHash, &out.DeliveryAuditSequence, &out.DeliveryAuditHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}
