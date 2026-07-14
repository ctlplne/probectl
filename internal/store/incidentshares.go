// SPDX-License-Identifier: LicenseRef-probectl-TBD

package store

import (
	"context"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// IncidentShares persists redacted, expiring incident-room snapshots. RLS is
// the outer boundary, and every statement also carries tenant_id explicitly so
// a future policy regression still cannot turn an ID into a cross-tenant read.
type IncidentShares struct{}

type IncidentShareInput struct {
	ID         string
	IncidentID string
	Payload    []byte
	CreatedBy  string
	ExpiresAt  time.Time
}

type IncidentShareArtifact struct {
	ID         string
	IncidentID string
	Payload    []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

func (IncidentShares) Create(ctx context.Context, s tenancy.Scope, in IncidentShareInput) (*IncidentShareArtifact, error) {
	var out IncidentShareArtifact
	err := s.Q.QueryRow(ctx, `
		INSERT INTO incident_share_artifacts
		       (tenant_id, id, incident_id, payload, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, incident_id::text, payload, created_at, expires_at`,
		s.Tenant.String(), in.ID, in.IncidentID, in.Payload, in.CreatedBy, in.ExpiresAt,
	).Scan(&out.ID, &out.IncidentID, &out.Payload, &out.CreatedAt, &out.ExpiresAt)
	if err != nil {
		return nil, mapWriteErr("incident share artifact", err)
	}
	return &out, nil
}

// Get returns only a live artifact in this tenant. Missing, expired, revoked,
// and cross-tenant IDs intentionally collapse to the same not-found error.
func (IncidentShares) Get(ctx context.Context, s tenancy.Scope, id string) (*IncidentShareArtifact, error) {
	var out IncidentShareArtifact
	err := s.Q.QueryRow(ctx, `
		SELECT id, incident_id::text, payload, created_at, expires_at
		  FROM incident_share_artifacts
		 WHERE tenant_id = $1 AND id = $2
		   AND revoked_at IS NULL AND expires_at > clock_timestamp()`,
		s.Tenant.String(), id,
	).Scan(&out.ID, &out.IncidentID, &out.Payload, &out.CreatedAt, &out.ExpiresAt)
	if err != nil {
		return nil, notFound("incident share artifact", err)
	}
	return &out, nil
}

// Prune removes expired/revoked rows for this tenant. Creation calls it
// opportunistically; share volume is intentionally low.
func (IncidentShares) Prune(ctx context.Context, s tenancy.Scope) (int64, error) {
	tag, err := s.Q.Exec(ctx, `
		DELETE FROM incident_share_artifacts
		 WHERE tenant_id = $1
		   AND (expires_at <= clock_timestamp() OR revoked_at IS NOT NULL)`,
		s.Tenant.String())
	if err != nil {
		return 0, mapWriteErr("incident share artifact", err)
	}
	return tag.RowsAffected(), nil
}
