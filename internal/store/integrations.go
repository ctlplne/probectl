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

// ReserveOpen commits the single right to create an external ticket. The
// incident lookup also requires ownership in the same RLS scope as the claim.
func (IncidentIntegrations) ReserveOpen(ctx context.Context, s tenancy.Scope, incidentID, connector string) (bool, error) {
	tag, err := s.Q.Exec(ctx,
		`INSERT INTO incident_integrations (tenant_id, incident_id, connector, status)
		 SELECT tenant_id, id, $3, $4 FROM incidents WHERE tenant_id = $1 AND id = $2
		 ON CONFLICT (tenant_id, incident_id, connector) DO NOTHING`,
		s.Tenant.String(), incidentID, connector, notify.LinkOpening)
	return tag.RowsAffected() == 1, err
}

// CompleteOpen publishes a confirmed reference once, even if two workers
// recover the same uncertain response. Later update or resolve state wins.
func (IncidentIntegrations) CompleteOpen(ctx context.Context, s tenancy.Scope, l notify.Link) error {
	_, err := s.Q.Exec(ctx,
		`UPDATE incident_integrations SET external_ref = $4, status = $5, revision = $6, updated_at = now()
		  WHERE tenant_id = $1 AND incident_id = $2 AND connector = $3 AND status = $7`,
		s.Tenant.String(), l.IncidentID, l.Connector, l.ExternalRef, l.Status, l.Revision, notify.LinkOpening)
	return err
}

// ReleaseOpen removes only a reservation whose owner received a definite
// create rejection. It leaves a completed connector link intact.
func (IncidentIntegrations) ReleaseOpen(ctx context.Context, s tenancy.Scope, incidentID, connector string) error {
	_, err := s.Q.Exec(ctx,
		`DELETE FROM incident_integrations WHERE tenant_id = $1 AND incident_id = $2 AND connector = $3 AND status = $4`,
		s.Tenant.String(), incidentID, connector, notify.LinkOpening)
	return err
}

const openTicketScope = ` FROM incident_integrations l
	JOIN incidents i ON i.id = l.incident_id AND i.tenant_id = l.tenant_id
	WHERE l.tenant_id = $1 AND l.connector = $2 AND l.status = 'open'
	  AND l.external_ref <> '' AND i.status = 'open'`

// OpenTicketStatuses returns versioned links for one tenant's vendor readback.
func (IncidentIntegrations) OpenTicketStatuses(ctx context.Context, s tenancy.Scope, connector, after string, limit int) ([]notify.TicketStatusSnapshot, error) {
	rows, err := s.Q.Query(ctx, `SELECT i.id::text, l.external_ref, i.xmin::text, l.xmin::text`+openTicketScope+`
	  AND ($3 = '' OR i.id > NULLIF($3, '')::uuid) ORDER BY i.id LIMIT $4`,
		s.Tenant.String(), connector, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var snapshots []notify.TicketStatusSnapshot
	for rows.Next() {
		snapshot := notify.TicketStatusSnapshot{TenantID: s.Tenant.String(), Connector: connector}
		if err := rows.Scan(&snapshot.IncidentID, &snapshot.ExternalRef, &snapshot.IncidentVersion, &snapshot.LinkVersion); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, rows.Err()
}

// LockOpenTicketStatus rechecks the same incident and link after the vendor
// call. The caller holds both row locks through the local update.
func (IncidentIntegrations) LockOpenTicketStatus(ctx context.Context, s tenancy.Scope, snapshot notify.TicketStatusSnapshot) (bool, error) {
	var current bool
	err := s.Q.QueryRow(ctx, `SELECT true`+openTicketScope+`
	  AND i.id = $3 AND l.external_ref = $4 AND i.xmin::text = $5 AND l.xmin::text = $6
	  FOR UPDATE OF i, l`, s.Tenant.String(), snapshot.Connector, snapshot.IncidentID,
		snapshot.ExternalRef, snapshot.IncidentVersion, snapshot.LinkVersion).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return current, err
}

// FindByRef resolves a connector's external ref back to its link (inbound sync).
func (IncidentIntegrations) FindByRef(ctx context.Context, s tenancy.Scope, connector, externalRef string) (*notify.Link, error) {
	l, err := scanLink(s.Q.QueryRow(ctx,
		`SELECT `+integrationCols+` FROM incident_integrations
		  WHERE connector = $1 AND external_ref = $2 AND status <> $3`, connector, externalRef, notify.LinkOpening))
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
		  WHERE incident_id = $1 AND status <> $2 ORDER BY connector`, incidentID, notify.LinkOpening)
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
