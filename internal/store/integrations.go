// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// IncidentIntegrations is the tenant-scoped incident↔connector link repository
// (S33, F27). It backs notify.LinkStore: idempotency for outbound delivery
// (UNIQUE tenant+incident+connector) and the reverse lookup for inbound status
// sync. RLS confines every row to the caller's tenant (F50).
type IncidentIntegrations struct{}

const integrationCols = `tenant_id::text, incident_id::text, connector, external_ref, status, revision, created_at, updated_at`

func scanLink(row interface{ Scan(...any) error }) (*notify.Link, error) {
	var l notify.Link
	if err := row.Scan(&l.TenantID, &l.IncidentID, &l.Connector, &l.ExternalRef, &l.Status, &l.Revision, &l.CreatedAt, &l.UpdatedAt); err != nil {
		return nil, err
	}
	return &l, nil
}

// Get returns the link for (incident, connector) in the scope's tenant, or
// (nil, nil) if none.
func (IncidentIntegrations) Get(ctx context.Context, s tenancy.Scope, incidentID, connector string) (*notify.Link, error) {
	l, err := scanLink(s.Q.QueryRow(ctx,
		`SELECT `+integrationCols+` FROM incident_integrations
		  WHERE incident_id = $1 AND connector = $2`, incidentID, connector))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

// FindByRef resolves a connector's external ref back to its link (inbound sync).
func (IncidentIntegrations) FindByRef(ctx context.Context, s tenancy.Scope, connector, externalRef string) (*notify.Link, error) {
	l, err := scanLink(s.Q.QueryRow(ctx,
		`SELECT `+integrationCols+` FROM incident_integrations
		  WHERE connector = $1 AND external_ref = $2`, connector, externalRef))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return l, nil
}

// Upsert records or updates a link, keyed by (tenant, incident, connector). The
// tenant comes from the scope, never the link's TenantID field.
func (IncidentIntegrations) Upsert(ctx context.Context, s tenancy.Scope, l notify.Link) error {
	status := l.Status
	if status == "" {
		status = "open"
	}
	_, err := s.Q.Exec(ctx,
		`INSERT INTO incident_integrations (tenant_id, incident_id, connector, external_ref, status, revision, updated_at)
		   VALUES ($1, $2, $3, $4, $5, $6, now())
		 ON CONFLICT (tenant_id, incident_id, connector)
		   DO UPDATE SET external_ref = EXCLUDED.external_ref,
		                 status       = EXCLUDED.status,
		                 revision     = GREATEST(incident_integrations.revision, EXCLUDED.revision),
		                 updated_at   = now()`,
		s.Tenant.String(), l.IncidentID, l.Connector, l.ExternalRef, status, l.Revision)
	return err
}

// ListForIncident returns all connector links for an incident (UI / inspection).
func (IncidentIntegrations) ListForIncident(ctx context.Context, s tenancy.Scope, incidentID string) ([]notify.Link, error) {
	rows, err := s.Q.Query(ctx,
		`SELECT `+integrationCols+` FROM incident_integrations
		  WHERE incident_id = $1 ORDER BY connector`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []notify.Link{}
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *l)
	}
	return out, rows.Err()
}
