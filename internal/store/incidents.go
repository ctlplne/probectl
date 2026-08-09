// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat"
)

// Incidents is the tenant-scoped incident repository. RLS confines every row to
// the caller's tenant (F50), so correlation and the timeline never cross tenants.
type Incidents struct{}

const incidentCols = `id::text, tenant_id::text, status, severity, title, target, prefix,
	started_at, last_seen_at, resolved_at, signal_count`

const correlationOverrideCols = `id::text, tenant_id::text, source_incident_id::text,
	detached_incident_id::text, source_signal_id::text, plane, kind, target, prefix,
	reason, active, created_by, created_at, reversed_by, reversal_reason, reversed_at`

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
		`SELECT id::text, plane, kind, severity, title, summary, target, prefix, attributes, occurred_at
		 FROM incident_signals WHERE incident_id = $1 ORDER BY occurred_at, id LIMIT $2`,
		id, incident.MaxSignalsPerRead+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if len(inc.Signals) == incident.MaxSignalsPerRead {
			inc.SignalsTruncated = true
			inc.SignalsLimit = incident.MaxSignalsPerRead
			break
		}
		var sig incident.Signal
		var severity string
		var attrs []byte
		if err := rows.Scan(&sig.ID, &sig.Plane, &sig.Kind, &severity, &sig.Title, &sig.Summary,
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
	if inc.SignalCount > len(inc.Signals) {
		inc.SignalsTruncated = true
		inc.SignalsLimit = incident.MaxSignalsPerRead
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return nil, rowErr
	}
	overrides, err := (Incidents{}).ListCorrelationOverrides(ctx, s, id)
	if err != nil {
		return nil, err
	}
	inc.CorrelationOverrides = overrides
	return &inc, nil
}

func scanCorrelationOverride(row interface{ Scan(...any) error }, override *incident.CorrelationOverride) error {
	return row.Scan(
		&override.ID, &override.TenantID, &override.SourceIncidentID,
		&override.DetachedIncidentID, &override.SourceSignalID, &override.Plane,
		&override.Kind, &override.Target, &override.Prefix, &override.Reason,
		&override.Active, &override.CreatedBy, &override.CreatedAt,
		&override.ReversedBy, &override.ReversalReason, &override.ReversedAt,
	)
}

// ActiveCorrelationOverrides returns active exclusions matching this exact
// signal shape. RLS is the outer boundary; the explicit tenant predicate is
// defense in depth and supports the match index.
func (Incidents) ActiveCorrelationOverrides(ctx context.Context, s tenancy.Scope, sig incident.Signal) ([]incident.CorrelationOverride, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+correlationOverrideCols+`
		FROM incident_correlation_overrides
		WHERE tenant_id = $1 AND active AND plane = $2 AND kind = $3 AND target = $4 AND prefix = $5
		ORDER BY created_at DESC`,
		s.Tenant.String(), sig.Plane, sig.Kind, sig.Target, sig.Prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []incident.CorrelationOverride{}
	for rows.Next() {
		var override incident.CorrelationOverride
		if err := scanCorrelationOverride(rows, &override); err != nil {
			return nil, err
		}
		out = append(out, override)
	}
	return out, rows.Err()
}

// ListCorrelationOverrides returns active and reversed rows for one source
// incident so operator intent and its reversal remain visible.
func (Incidents) ListCorrelationOverrides(ctx context.Context, s tenancy.Scope, incidentID string) ([]incident.CorrelationOverride, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+correlationOverrideCols+`
		FROM incident_correlation_overrides WHERE source_incident_id = $1
		ORDER BY created_at DESC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []incident.CorrelationOverride{}
	for rows.Next() {
		var override incident.CorrelationOverride
		if err := scanCorrelationOverride(rows, &override); err != nil {
			return nil, err
		}
		out = append(out, override)
	}
	return out, rows.Err()
}

// CreateUngroupOverride preserves the original evidence, creates a standalone
// incident from the selected signal, and installs the durable exclusion used by
// every later correlation run. The caller and audit append share the tenant
// transaction.
func (Incidents) CreateUngroupOverride(ctx context.Context, s tenancy.Scope, sourceIncidentID, sourceSignalID, reason, actor string) (*incident.CorrelationOverride, *incident.Incident, error) {
	if _, err := s.Q.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text, 0))`,
		s.Tenant.String()); err != nil {
		return nil, nil, err
	}
	var source incident.Signal
	var severity string
	var attrs []byte
	err := s.Q.QueryRow(ctx, `SELECT id::text, plane, kind, severity, title, summary, target, prefix, attributes, occurred_at
		FROM incident_signals WHERE id = $1 AND incident_id = $2`, sourceSignalID, sourceIncidentID).Scan(
		&source.ID, &source.Plane, &source.Kind, &severity, &source.Title,
		&source.Summary, &source.Target, &source.Prefix, &attrs, &source.OccurredAt)
	if err != nil {
		return nil, nil, notFound("incident signal", err)
	}
	source.TenantID = s.Tenant.String()
	source.Severity = incident.Severity(severity)
	source.Attributes = map[string]string{}
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &source.Attributes); err != nil {
			return nil, nil, err
		}
	}
	var sourceCount int
	if err := s.Q.QueryRow(ctx, `SELECT signal_count FROM incidents WHERE id = $1`, sourceIncidentID).Scan(&sourceCount); err != nil {
		return nil, nil, notFound("incident", err)
	}
	if sourceCount <= 1 {
		return nil, nil, apierror.Conflict("the only signal is already an independent incident")
	}
	var exists bool
	if err := s.Q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM incident_correlation_overrides
		WHERE source_incident_id = $1 AND plane = $2 AND kind = $3 AND target = $4 AND prefix = $5 AND active
	)`, sourceIncidentID, source.Plane, source.Kind, source.Target, source.Prefix).Scan(&exists); err != nil {
		return nil, nil, err
	}
	if exists {
		return nil, nil, apierror.Conflict("an active override already covers this signal shape")
	}

	child, err := (Incidents{}).Create(ctx, s, incident.Incident{
		TenantID: s.Tenant.String(), Status: incident.StatusOpen, Severity: source.Severity,
		Title: source.Title, Target: source.Target, Prefix: source.Prefix,
		StartedAt: source.OccurredAt, LastSeenAt: source.OccurredAt,
	})
	if err != nil {
		return nil, nil, err
	}
	var override incident.CorrelationOverride
	err = scanCorrelationOverride(s.Q.QueryRow(ctx, `INSERT INTO incident_correlation_overrides
		(tenant_id, source_incident_id, detached_incident_id, source_signal_id,
		 plane, kind, target, prefix, reason, active, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, $10)
		RETURNING `+correlationOverrideCols,
		s.Tenant.String(), sourceIncidentID, child.ID, sourceSignalID,
		source.Plane, source.Kind, source.Target, source.Prefix, strings.TrimSpace(reason), actor), &override)
	if err != nil {
		return nil, nil, mapWriteErr("incident correlation override", err)
	}
	clone := source
	clone.ID = ""
	clone.Attributes = copyStringMap(source.Attributes)
	clone.Attributes["correlation.state"] = "root"
	clone.Attributes["correlation.parent_incident_id"] = child.ID
	clone.Attributes["correlation.reason"] = "operator_ungroup_override_created_independent_incident"
	clone.Attributes["correlation.override_id"] = override.ID
	clone.Attributes["correlation.excluded_parent_incident_id"] = sourceIncidentID
	clone.Attributes["correlation.match_confidence"] = "operator_decision"
	detached, err := (Incidents{}).AppendSignal(ctx, s, child.ID, clone)
	if err != nil {
		return nil, nil, err
	}
	if _, err := s.Q.Exec(ctx, `UPDATE incident_signals
		SET attributes = attributes || jsonb_build_object(
		  'correlation.override_id', $2::text,
		  'correlation.detached_incident_id', $3::text,
		  'correlation.override_state', 'active')
		WHERE id = $1`, sourceSignalID, override.ID, child.ID); err != nil {
		return nil, nil, err
	}
	return &override, detached, nil
}

// ReverseCorrelationOverride removes the exclusion for later correlation runs;
// it never deletes either timeline.
func (Incidents) ReverseCorrelationOverride(ctx context.Context, s tenancy.Scope, sourceIncidentID, overrideID, actor, reason string) (*incident.CorrelationOverride, error) {
	var override incident.CorrelationOverride
	err := scanCorrelationOverride(s.Q.QueryRow(ctx, `UPDATE incident_correlation_overrides SET
		active = false, reversed_by = $3, reversal_reason = $4, reversed_at = now()
		WHERE id = $1 AND source_incident_id = $2 AND active
		RETURNING `+correlationOverrideCols,
		overrideID, sourceIncidentID, actor, strings.TrimSpace(reason)), &override)
	if err != nil {
		return nil, notFound("active incident correlation override", err)
	}
	if _, err := s.Q.Exec(ctx, `UPDATE incident_signals
		SET attributes = attributes || jsonb_build_object('correlation.override_state', 'reversed')
		WHERE id = $1`, override.SourceSignalID); err != nil {
		return nil, err
	}
	return &override, nil
}

func copyStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+8)
	for key, value := range in {
		out[key] = value
	}
	return out
}

// ThreatDetections returns recent attributed threat signals from the durable
// incident timeline. The caller supplies a tenant-scoped Scope, so RLS confines
// the read before the WHERE clause runs; this is the shared-store backing for
// GET /v1/threat/detections in HA deployments.
func (Incidents) ThreatDetections(ctx context.Context, s tenancy.Scope, limit int) ([]threat.Detection, error) {
	if limit <= 0 || limit > threat.DefaultMaxDetectionsPerTenant {
		limit = threat.DefaultMaxDetectionsPerTenant
	}
	rows, err := s.Q.Query(ctx,
		`SELECT incident_id::text, kind, severity, title, summary, target, attributes, occurred_at
		   FROM incident_signals
		  WHERE plane = 'threat'
		    AND (attributes ? 'intel.source' OR attributes ? 'detector.rule')
		  ORDER BY occurred_at DESC
		  LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []threat.Detection{}
	for rows.Next() {
		var sig incident.Signal
		var incidentID, severity string
		var attrs []byte
		if err := rows.Scan(&incidentID, &sig.Kind, &severity, &sig.Title, &sig.Summary,
			&sig.Target, &attrs, &sig.OccurredAt); err != nil {
			return nil, err
		}
		sig.TenantID = s.Tenant.String()
		sig.Plane = "threat"
		sig.Severity = incident.Severity(severity)
		sig.Attributes = map[string]string{}
		if len(attrs) > 0 {
			if err := json.Unmarshal(attrs, &sig.Attributes); err != nil {
				return nil, err
			}
		}
		if d, ok := threat.DetectionFromSignal(sig, incidentID); ok {
			out = append(out, d)
		}
	}
	return out, rows.Err()
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

// Reopen marks an incident open again after an explicit human decision. It does
// not erase history; resolved_at is cleared while the original timeline stays.
func (Incidents) Reopen(ctx context.Context, s tenancy.Scope, id string) (*incident.Incident, error) {
	var inc incident.Incident
	err := scanIncident(s.Q.QueryRow(ctx,
		`UPDATE incidents SET status = 'open', resolved_at = NULL
		 WHERE id = $1 RETURNING `+incidentCols, id), &inc)
	if err != nil {
		return nil, notFound("incident", err)
	}
	return &inc, nil
}
