package store

import (
	"context"
	"encoding/json"

	"github.com/imfeelingtheagi/netctl/internal/incident"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
)

// Incidents is the tenant-scoped incident repository. RLS confines every row to
// the caller's tenant (F50), so correlation and the timeline never cross tenants.
type Incidents struct{}

const incidentCols = `id::text, tenant_id::text, status, severity, title, target, prefix,
	started_at, last_seen_at, resolved_at, signal_count`

func scanIncident(row interface{ Scan(...any) error }, inc *incident.Incident) error {
	var status, severity string
	if err := row.Scan(&inc.ID, &inc.TenantID, &status, &severity, &inc.Title, &inc.Target,
		&inc.Prefix, &inc.StartedAt, &inc.LastSeenAt, &inc.ResolvedAt, &inc.SignalCount); err != nil {
		return err
	}
	inc.Status = incident.Status(status)
	inc.Severity = incident.Severity(severity)
	return nil
}

// Create inserts a new open incident seeded from a signal.
func (Incidents) Create(ctx context.Context, s tenancy.Scope, in incident.Incident) (*incident.Incident, error) {
	var inc incident.Incident
	err := scanIncident(s.Q.QueryRow(ctx,
		`INSERT INTO incidents
		   (tenant_id, status, severity, severity_rank, title, target, prefix, started_at, last_seen_at, signal_count)
		 VALUES ($1, 'open', $2, $3, $4, $5, $6, $7, $8, 0)
		 RETURNING `+incidentCols,
		s.Tenant.String(), string(in.Severity), incident.SeverityRank(in.Severity),
		in.Title, in.Target, in.Prefix, in.StartedAt, in.LastSeenAt), &inc)
	if err != nil {
		return nil, mapWriteErr("incident", err)
	}
	return &inc, nil
}

// OpenIncidents returns the tenant's open incidents, most-recently-active first
// (the correlation candidate set).
func (Incidents) OpenIncidents(ctx context.Context, s tenancy.Scope) ([]incident.Incident, error) {
	return queryIncidents(ctx, s, `SELECT `+incidentCols+`
		FROM incidents WHERE status = 'open' ORDER BY last_seen_at DESC LIMIT 200`)
}

// List returns the tenant's incidents, most-recently-active first.
func (Incidents) List(ctx context.Context, s tenancy.Scope) ([]incident.Incident, error) {
	return queryIncidents(ctx, s, `SELECT `+incidentCols+`
		FROM incidents ORDER BY last_seen_at DESC LIMIT 500`)
}

func queryIncidents(ctx context.Context, s tenancy.Scope, sql string) ([]incident.Incident, error) {
	rows, err := s.Q.Query(ctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []incident.Incident{}
	for rows.Next() {
		var inc incident.Incident
		if err := scanIncident(rows, &inc); err != nil {
			return nil, err
		}
		out = append(out, inc)
	}
	return out, rows.Err()
}

// Get returns an incident with its full signal timeline (time-ordered).
func (Incidents) Get(ctx context.Context, s tenancy.Scope, id string) (*incident.Incident, error) {
	var inc incident.Incident
	if err := scanIncident(s.Q.QueryRow(ctx,
		`SELECT `+incidentCols+` FROM incidents WHERE id = $1`, id), &inc); err != nil {
		return nil, notFound("incident", err)
	}
	rows, err := s.Q.Query(ctx,
		`SELECT plane, kind, severity, title, summary, target, prefix, attributes, occurred_at
		 FROM incident_signals WHERE incident_id = $1 ORDER BY occurred_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sig incident.Signal
		var severity string
		var attrs []byte
		if err := rows.Scan(&sig.Plane, &sig.Kind, &severity, &sig.Title, &sig.Summary,
			&sig.Target, &sig.Prefix, &attrs, &sig.OccurredAt); err != nil {
			return nil, err
		}
		sig.Severity = incident.Severity(severity)
		sig.TenantID = inc.TenantID
		sig.Attributes = map[string]string{}
		if len(attrs) > 0 {
			if err := json.Unmarshal(attrs, &sig.Attributes); err != nil {
				return nil, err
			}
		}
		inc.Signals = append(inc.Signals, sig)
	}
	return &inc, rows.Err()
}

// AppendSignal inserts a signal and atomically updates the incident's last-seen,
// severity (max), and signal count, returning the refreshed incident. The caller
// runs this inside a tenant-scoped transaction (tenancy.InTenant), so the insert
// and update are atomic.
func (Incidents) AppendSignal(ctx context.Context, s tenancy.Scope, incidentID string, sig incident.Signal) (*incident.Incident, error) {
	attrs := "{}"
	if sig.Attributes != nil {
		b, err := json.Marshal(sig.Attributes)
		if err != nil {
			return nil, err
		}
		attrs = string(b)
	}
	if _, err := s.Q.Exec(ctx,
		`INSERT INTO incident_signals
		   (tenant_id, incident_id, plane, kind, severity, title, summary, target, prefix, attributes, occurred_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11)`,
		s.Tenant.String(), incidentID, sig.Plane, sig.Kind, string(sig.Severity),
		sig.Title, sig.Summary, sig.Target, sig.Prefix, attrs, sig.OccurredAt); err != nil {
		return nil, err
	}

	var inc incident.Incident
	err := scanIncident(s.Q.QueryRow(ctx,
		`UPDATE incidents SET
		   signal_count  = signal_count + 1,
		   last_seen_at  = GREATEST(last_seen_at, $2),
		   started_at    = LEAST(started_at, $2),
		   severity      = CASE WHEN $3 > severity_rank THEN $4 ELSE severity END,
		   severity_rank = GREATEST(severity_rank, $3)
		 WHERE id = $1
		 RETURNING `+incidentCols,
		incidentID, sig.OccurredAt, incident.SeverityRank(sig.Severity), string(sig.Severity)), &inc)
	if err != nil {
		return nil, notFound("incident", err)
	}
	return &inc, nil
}

// Resolve marks an incident resolved.
func (Incidents) Resolve(ctx context.Context, s tenancy.Scope, id string) (*incident.Incident, error) {
	var inc incident.Incident
	err := scanIncident(s.Q.QueryRow(ctx,
		`UPDATE incidents SET status = 'resolved', resolved_at = now()
		 WHERE id = $1 RETURNING `+incidentCols, id), &inc)
	if err != nil {
		return nil, notFound("incident", err)
	}
	return &inc, nil
}
