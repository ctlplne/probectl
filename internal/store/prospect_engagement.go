// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type ProspectEngagement struct {
	Revision             int64      `json:"revision"`
	AssessmentViewID     string     `json:"assessment_view_id"`
	AssessmentAt         time.Time  `json:"assessment_view_revision"`
	Preparer             string     `json:"preparer"`
	StartsAt             time.Time  `json:"starts_at"`
	EndsAt               time.Time  `json:"ends_at"`
	ConvertedAt          *time.Time `json:"converted_at,omitempty"`
	ConsentedAt          *time.Time `json:"consented_at,omitempty"`
	ConsentRevokedAt     *time.Time `json:"consent_revoked_at,omitempty"`
	DestinationID        string     `json:"destination_id,omitempty"`
	AssessmentArtifactID string     `json:"assessment_artifact_id,omitempty"`

	OwnerID         string `json:"-"`
	TenantSlug      string `json:"-"`
	ConsentRevision *int64 `json:"-"`
}

type ProspectEngagements struct{}

func (e ProspectEngagement) HasCurrentDeliveryConsent() bool {
	return e.ConsentedAt != nil && e.ConsentRevision != nil && *e.ConsentRevision == e.Revision &&
		e.ConsentRevokedAt == nil && e.ConvertedAt == nil && e.DestinationID != ""
}

const prospectEngagementColumns = `revision,assessment_view_id,assessment_view_revision,preparer,starts_at,ends_at,
	converted_at,consented_at,consent_revoked_at,COALESCE(consent_destination_id,''),owner_id::text,tenant_slug,consent_revision,
	COALESCE(assessment_artifact_id,'')`

func scanProspectEngagement(row pgx.Row) (ProspectEngagement, error) {
	var out ProspectEngagement
	err := row.Scan(&out.Revision, &out.AssessmentViewID, &out.AssessmentAt, &out.Preparer, &out.StartsAt, &out.EndsAt,
		&out.ConvertedAt, &out.ConsentedAt, &out.ConsentRevokedAt, &out.DestinationID, &out.OwnerID, &out.TenantSlug, &out.ConsentRevision,
		&out.AssessmentArtifactID)
	return out, err
}

// FileAssessment associates one sealed report with the exact completed
// engagement. The caller inserts the artifact, files it and appends the audit
// under the same scoped transaction.
func (ProspectEngagements) FileAssessment(ctx context.Context, sc tenancy.Scope, revision int64, artifactID string, at time.Time) error {
	if err := prospectScope(ctx, sc); err != nil {
		return err
	}
	tag, err := sc.Q.Exec(ctx, `UPDATE prospect_engagements engagement SET assessment_artifact_id=$3
		WHERE engagement.tenant_id=$1 AND engagement.revision=$2 AND engagement.ends_at<=$4
		 AND engagement.converted_at IS NULL AND engagement.assessment_artifact_id IS NULL
		 AND EXISTS (SELECT 1 FROM dashboard_report_artifacts artifact
		  WHERE artifact.tenant_id=engagement.tenant_id AND artifact.id=$3 AND artifact.dashboard_id=engagement.assessment_view_id
		   AND artifact.absolute_from=engagement.starts_at AND artifact.absolute_to=engagement.ends_at
		   AND artifact.body_storage='chunks' AND artifact.body_bytes>0 AND octet_length(artifact.body_digest)=32)`,
		sc.Tenant.String(), revision, artifactID, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return apierror.Conflict("the completed prospect engagement or sealed assessment changed")
	}
	return nil
}

func prospectScope(ctx context.Context, sc tenancy.Scope) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || sc.Q == nil || sc.Tenant != bound {
		return tenancy.ErrNoTenant
	}
	return ctx.Err()
}

func (ProspectEngagements) Get(ctx context.Context, sc tenancy.Scope) (ProspectEngagement, error) {
	if err := prospectScope(ctx, sc); err != nil {
		return ProspectEngagement{}, err
	}
	out, err := scanProspectEngagement(sc.Q.QueryRow(ctx, `SELECT `+prospectEngagementColumns+`
		FROM prospect_engagements WHERE tenant_id=$1`, sc.Tenant.String()))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProspectEngagement{}, apierror.NotFound("prospect engagement not found")
	}
	return out, err
}

// Create records an engagement and any initial consent under the exact owned
// report definition and stable actor. It does not confer erasure authority on
// a caller who merely holds the resulting revision or destination identifier.
func (ProspectEngagements) Create(ctx context.Context, sc tenancy.Scope, in ProspectEngagement) (ProspectEngagement, error) {
	if err := prospectScope(ctx, sc); err != nil {
		return ProspectEngagement{}, err
	}
	out, err := scanProspectEngagement(sc.Q.QueryRow(ctx, `INSERT INTO prospect_engagements (
		tenant_id,revision,tenant_slug,owner_id,assessment_view_id,assessment_view_revision,preparer,starts_at,ends_at,
		consented_at,consent_revision,consent_destination_id)
		SELECT $1,1,$2,$3,$4,$5,$9,$6,$7,CASE WHEN $8<>'' THEN $6::timestamptz END,
		 CASE WHEN $8<>'' THEN 1 END,NULLIF($8,'')
		FROM dashboard_views view
		JOIN users account ON account.tenant_id=view.tenant_id AND account.id=$3 AND account.status='active'
		WHERE view.tenant_id=$1 AND view.owner_id=$3::uuid::text AND view.id=$4 AND view.updated_at=$5
		ON CONFLICT (tenant_id) DO NOTHING RETURNING `+prospectEngagementColumns,
		sc.Tenant.String(), in.TenantSlug, in.OwnerID, in.AssessmentViewID, in.AssessmentAt, in.StartsAt, in.EndsAt, in.DestinationID, in.Preparer))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProspectEngagement{}, apierror.Conflict("the prospect engagement already exists or the owned assessment revision changed")
	}
	return out, err
}

// Decide updates the exact revision. Conversion and consent withdrawal both
// invalidate an earlier authorization in the same tenant-owned write.
func (ProspectEngagements) Decide(ctx context.Context, sc tenancy.Scope, revision int64, convert bool, at time.Time) (ProspectEngagement, error) {
	if err := prospectScope(ctx, sc); err != nil {
		return ProspectEngagement{}, err
	}
	out, err := scanProspectEngagement(sc.Q.QueryRow(ctx, `UPDATE prospect_engagements
		SET revision=revision+1,converted_at=CASE WHEN $3 THEN $4::timestamptz ELSE converted_at END,
		 consent_revoked_at=CASE WHEN consented_at IS NOT NULL THEN COALESCE(consent_revoked_at,$4) END
		WHERE tenant_id=$1 AND revision=$2 AND converted_at IS NULL
		 AND ($3 OR consented_at IS NOT NULL AND consent_revoked_at IS NULL)
		RETURNING `+prospectEngagementColumns, sc.Tenant.String(), revision, convert, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProspectEngagement{}, apierror.Conflict("the prospect engagement or its consent changed")
	}
	return out, err
}
