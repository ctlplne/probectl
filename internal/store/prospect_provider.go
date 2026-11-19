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

type ProspectProviderAccess struct {
	Revision           int64 `json:"revision"`
	EngagementRevision int64 `json:"engagement_revision"`
	Allowed            bool  `json:"allowed"`
	CanGrant           bool  `json:"can_grant"`
}

type ProspectProviderStatus struct {
	Phase          string
	EndsAt         time.Time
	Pending        bool
	Revision       int64
	AccessRevision int64
	RequestID      string
}

// ProviderAccess reads the same scoped row used for user consent and lifecycle.
// The caller has lifecycle authority. Only the engagement owner can grant.
func (ProspectEngagements) ProviderAccess(ctx context.Context, sc tenancy.Scope, owner string) (ProspectProviderAccess, error) {
	var access ProspectProviderAccess
	if err := prospectScope(ctx, sc); err != nil {
		return access, err
	}
	err := sc.Q.QueryRow(ctx, `SELECT provider_access_revision,revision,
		COALESCE(provider_engagement_revision=revision AND converted_at IS NULL,false),
		owner_id=$2 AND converted_at IS NULL
		FROM prospect_engagements WHERE tenant_id=$1`, sc.Tenant.String(), owner).
		Scan(&access.Revision, &access.EngagementRevision, &access.Allowed, &access.CanGrant)
	if errors.Is(err, pgx.ErrNoRows) {
		return access, apierror.NotFound("prospect engagement not found")
	}
	return access, err
}

// SetProviderAccess requires both exact revisions and the owning account for
// a grant. The caller holds current lifecycle authority, the tenant write
// lease and the audit lock, and records the decision in the same transaction.
func (ProspectEngagements) SetProviderAccess(ctx context.Context, sc tenancy.Scope, owner string, engagement, grant int64, allow bool) (ProspectProviderAccess, error) {
	var access ProspectProviderAccess
	if err := prospectScope(ctx, sc); err != nil {
		return access, err
	}
	err := sc.Q.QueryRow(ctx, `UPDATE prospect_engagements
		SET provider_access_revision=provider_access_revision+1,
			provider_engagement_revision=CASE WHEN $5 THEN revision END,
			provider_request_id=NULL
		WHERE tenant_id=$1 AND (NOT $5 OR owner_id=$2) AND revision=$3 AND provider_access_revision=$4
			AND converted_at IS NULL AND provider_access_revision<9223372036854775807
		RETURNING provider_access_revision,revision,provider_engagement_revision IS NOT NULL,owner_id=$2`,
		sc.Tenant.String(), owner, engagement, grant, allow).Scan(&access.Revision, &access.EngagementRevision, &access.Allowed, &access.CanGrant)
	if errors.Is(err, pgx.ErrNoRows) {
		return access, apierror.Conflict("the owning engagement or provider grant changed")
	}
	return access, err
}

// ProviderStatus returns only operational metadata. The owner identifier is
// used inside the same transaction to recheck authority and is never returned
// in the provider response.
func (ProspectEngagements) ProviderStatus(ctx context.Context, sc tenancy.Scope) (ProspectProviderStatus, string, error) {
	var status ProspectProviderStatus
	var owner string
	if err := prospectScope(ctx, sc); err != nil {
		return status, owner, err
	}
	err := sc.Q.QueryRow(ctx, `SELECT CASE WHEN ends_at>clock_timestamp() THEN 'collecting'
		WHEN assessment_artifact_id IS NULL THEN 'due' ELSE 'filed' END,
		ends_at,provider_request_id IS NOT NULL AND assessment_artifact_id IS NULL,owner_id::text,
		revision,provider_access_revision,COALESCE(provider_request_id::text,'')
		FROM prospect_engagements WHERE tenant_id=$1
		  AND provider_engagement_revision=revision AND converted_at IS NULL`,
		sc.Tenant.String()).Scan(&status.Phase, &status.EndsAt, &status.Pending, &owner, &status.Revision, &status.AccessRevision, &status.RequestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return status, "", apierror.NotFound("prospect operation unavailable")
	}
	return status, owner, err
}

// QueueProviderAssessment records one request for the current revision under
// the same tenant, write lease and audit lock. The caller audits each new
// request with the original provider attribution.
func (ProspectEngagements) QueueProviderAssessment(ctx context.Context, sc tenancy.Scope, request string, engagement, access int64) (bool, error) {
	if err := prospectScope(ctx, sc); err != nil {
		return false, err
	}
	tag, err := sc.Q.Exec(ctx, `UPDATE prospect_engagements SET provider_request_id=$2
		WHERE tenant_id=$1 AND provider_engagement_revision=revision AND converted_at IS NULL
		  AND revision=$3 AND provider_access_revision=$4
		  AND ends_at<=clock_timestamp() AND assessment_artifact_id IS NULL AND provider_request_id IS NULL`,
		sc.Tenant.String(), request, engagement, access)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// CurrentProviderRequest is checked when a provider wakeup is accepted and
// again in the report's scoped publication transaction.
func (ProspectEngagements) CurrentProviderRequest(ctx context.Context, sc tenancy.Scope, request string, engagement, access int64) (bool, error) {
	if err := prospectScope(ctx, sc); err != nil {
		return false, err
	}
	var current bool
	err := sc.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM prospect_engagements
		WHERE tenant_id=$1 AND provider_request_id=$2 AND provider_engagement_revision=revision
		  AND revision=$3 AND provider_access_revision=$4
		  AND converted_at IS NULL AND ends_at<=clock_timestamp() AND assessment_artifact_id IS NULL)`,
		sc.Tenant.String(), request, engagement, access).Scan(&current)
	return current, err
}
