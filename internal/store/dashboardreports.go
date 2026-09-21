// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DashboardReports persists operator-authored dashboard definitions, local
// schedules, and generated artifacts. Every statement carries tenant_id even
// though Postgres RLS is also FORCEd: the explicit predicate is the inner belt,
// while RLS is the outer safety wall.
type DashboardReports struct{}

type DashboardViewInput struct {
	ID         string
	OwnerID    string
	Name       string
	Preset     string
	Shared     bool
	Definition json.RawMessage
}

type DashboardView struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	OwnerID    string          `json:"owner_id"`
	Name       string          `json:"name"`
	Preset     string          `json:"preset"`
	Shared     bool            `json:"shared"`
	Definition json.RawMessage `json:"definition"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type ReportScheduleInput struct {
	ID            string
	DashboardID   string
	OwnerID       string
	Name          string
	Format        string
	Cadence       string
	DestinationID string
	NextRunAt     time.Time
}

type ReportSchedule struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	DashboardID   string     `json:"dashboard_id"`
	OwnerID       string     `json:"owner_id"`
	Name          string     `json:"name"`
	Format        string     `json:"format"`
	Cadence       string     `json:"cadence"`
	DestinationID string     `json:"destination_id"`
	Enabled       bool       `json:"enabled"`
	NextRunAt     time.Time  `json:"next_run_at"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type ReportArtifactInput struct {
	ID                  string
	DashboardID         string
	ScheduleID          *string
	Format              string
	MediaType           string
	Filename            string
	Content             []byte
	GeneratedBy         string
	AbsoluteFrom        time.Time
	AbsoluteTo          time.Time
	Provenance          []string
	RedactionState      string
	CoverageLimitations []string
}

type ReportArtifact struct {
	ID                  string          `json:"id"`
	TenantID            string          `json:"tenant_id"`
	DashboardID         string          `json:"dashboard_id"`
	ScheduleID          *string         `json:"schedule_id,omitempty"`
	Format              string          `json:"format"`
	MediaType           string          `json:"media_type"`
	Filename            string          `json:"filename"`
	Content             []byte          `json:"-"`
	GeneratedBy         string          `json:"generated_by"`
	GeneratedAt         time.Time       `json:"generated_at"`
	AbsoluteFrom        time.Time       `json:"absolute_from"`
	AbsoluteTo          time.Time       `json:"absolute_to"`
	Provenance          json.RawMessage `json:"provenance"`
	RedactionState      string          `json:"redaction_state"`
	CoverageLimitations json.RawMessage `json:"coverage_limitations"`
}

// DueDashboardReport is one locked schedule plus the tenant-local saved view
// it will render. The lock lives for the surrounding tenancy.Scope transaction,
// so HA workers use SKIP LOCKED without producing duplicate artifacts.
type DueDashboardReport struct {
	Schedule ReportSchedule
	View     DashboardView
}

const dashboardViewColumns = `id, tenant_id::text, owner_id, name, preset, shared,
 definition, created_at, updated_at`

func scanDashboardView(row interface{ Scan(...any) error }, out *DashboardView) error {
	var definition []byte
	if err := row.Scan(&out.ID, &out.TenantID, &out.OwnerID, &out.Name, &out.Preset,
		&out.Shared, &definition, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return notFound("dashboard view", err)
	}
	out.Definition = append(out.Definition[:0], definition...)
	return nil
}

func (DashboardReports) CreateView(ctx context.Context, s tenancy.Scope, in DashboardViewInput) (*DashboardView, error) {
	if !json.Valid(in.Definition) {
		return nil, apierror.Validation("dashboard definition is not valid JSON")
	}
	var out DashboardView
	err := scanDashboardView(s.Q.QueryRow(ctx, `
		INSERT INTO dashboard_views
		       (tenant_id, id, owner_id, name, preset, shared, definition)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
		RETURNING `+dashboardViewColumns,
		s.Tenant.String(), in.ID, in.OwnerID, in.Name, in.Preset, in.Shared, in.Definition), &out)
	if err != nil {
		return nil, mapWriteErr("dashboard view", err)
	}
	return &out, nil
}

// GetView returns a dashboard only if it is owned by the caller or explicitly
// shared inside the same tenant. Missing, unauthorized, and cross-tenant IDs
// are deliberately indistinguishable.
func (DashboardReports) GetView(ctx context.Context, s tenancy.Scope, id, userID string) (*DashboardView, error) {
	var out DashboardView
	err := scanDashboardView(s.Q.QueryRow(ctx, `
		SELECT `+dashboardViewColumns+`
		  FROM dashboard_views
		 WHERE tenant_id = $1 AND id = $2 AND (owner_id = $3 OR shared)`,
		s.Tenant.String(), id, userID), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (DashboardReports) ListViews(ctx context.Context, s tenancy.Scope, userID string) ([]DashboardView, error) {
	rows, err := s.Q.Query(ctx, `
		SELECT `+dashboardViewColumns+`
		  FROM dashboard_views
		 WHERE tenant_id = $1 AND (owner_id = $2 OR shared)
		 ORDER BY updated_at DESC, id LIMIT 200`, s.Tenant.String(), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DashboardView{}
	for rows.Next() {
		var item DashboardView
		if err := scanDashboardView(rows, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

const reportScheduleColumns = `id, tenant_id::text, dashboard_id, owner_id, name, format,
 cadence, destination_id, enabled, next_run_at, last_run_at, created_at, updated_at`

func scanReportSchedule(row interface{ Scan(...any) error }, out *ReportSchedule) error {
	if err := row.Scan(&out.ID, &out.TenantID, &out.DashboardID, &out.OwnerID, &out.Name,
		&out.Format, &out.Cadence, &out.DestinationID, &out.Enabled, &out.NextRunAt,
		&out.LastRunAt, &out.CreatedAt, &out.UpdatedAt); err != nil {
		return notFound("dashboard report schedule", err)
	}
	return nil
}

func (DashboardReports) CreateSchedule(ctx context.Context, s tenancy.Scope, in ReportScheduleInput) (*ReportSchedule, error) {
	// The join prevents a caller from scheduling a private view owned by another
	// user even if they guess its id. RLS independently prevents cross-tenant ids.
	var out ReportSchedule
	err := scanReportSchedule(s.Q.QueryRow(ctx, `
		INSERT INTO dashboard_report_schedules
		       (tenant_id, id, dashboard_id, owner_id, name, format, cadence, destination_id, next_run_at)
		SELECT $1, $2, v.id, $3, $4, $5, $6, $7, $8
		  FROM dashboard_views v
		 WHERE v.tenant_id = $1 AND v.id = $9 AND (v.owner_id = $3 OR v.shared)
		RETURNING `+reportScheduleColumns,
		s.Tenant.String(), in.ID, in.OwnerID, in.Name, in.Format, in.Cadence,
		in.DestinationID, in.NextRunAt, in.DashboardID), &out)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, notFound("dashboard view", err)
		}
		return nil, mapWriteErr("dashboard report schedule", err)
	}
	return &out, nil
}

func (DashboardReports) ListSchedules(ctx context.Context, s tenancy.Scope, userID string) ([]ReportSchedule, error) {
	rows, err := s.Q.Query(ctx, `
		SELECT `+reportScheduleColumns+`
		  FROM dashboard_report_schedules
		 WHERE tenant_id = $1 AND owner_id = $2
		 ORDER BY updated_at DESC, id LIMIT 200`, s.Tenant.String(), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportSchedule{}
	for rows.Next() {
		var item ReportSchedule
		if err := scanReportSchedule(rows, &item); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ClaimDue returns at most limit schedules due in this tenant and row-locks
// them until the caller atomically stores an artifact, advances next_run_at,
// and appends the audit event.
func (DashboardReports) ClaimDue(ctx context.Context, s tenancy.Scope, now time.Time, limit int) ([]DueDashboardReport, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.Q.Query(ctx, `
		SELECT s.id, s.tenant_id::text, s.dashboard_id, s.owner_id, s.name, s.format,
		       s.cadence, s.destination_id, s.enabled, s.next_run_at, s.last_run_at,
		       s.created_at, s.updated_at,
		       v.id, v.tenant_id::text, v.owner_id, v.name, v.preset, v.shared,
		       v.definition, v.created_at, v.updated_at
		  FROM dashboard_report_schedules s
		  JOIN dashboard_views v
		    ON v.tenant_id = s.tenant_id AND v.id = s.dashboard_id
		 WHERE s.tenant_id = $1 AND s.enabled AND s.next_run_at <= $2
		 ORDER BY s.next_run_at, s.id
		 FOR UPDATE OF s SKIP LOCKED
		 LIMIT $3`, s.Tenant.String(), now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DueDashboardReport{}
	for rows.Next() {
		var item DueDashboardReport
		var definition []byte
		if err := rows.Scan(
			&item.Schedule.ID, &item.Schedule.TenantID, &item.Schedule.DashboardID,
			&item.Schedule.OwnerID, &item.Schedule.Name, &item.Schedule.Format,
			&item.Schedule.Cadence, &item.Schedule.DestinationID, &item.Schedule.Enabled,
			&item.Schedule.NextRunAt, &item.Schedule.LastRunAt, &item.Schedule.CreatedAt,
			&item.Schedule.UpdatedAt,
			&item.View.ID, &item.View.TenantID, &item.View.OwnerID, &item.View.Name,
			&item.View.Preset, &item.View.Shared, &definition, &item.View.CreatedAt,
			&item.View.UpdatedAt,
		); err != nil {
			return nil, err
		}
		item.View.Definition = append(item.View.Definition[:0], definition...)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (DashboardReports) MarkScheduleDelivered(ctx context.Context, s tenancy.Scope, id string, deliveredAt, nextRunAt time.Time) error {
	tag, err := s.Q.Exec(ctx, `
		UPDATE dashboard_report_schedules
		   SET last_run_at = $3, next_run_at = $4, updated_at = $3
		 WHERE tenant_id = $1 AND id = $2 AND enabled`,
		s.Tenant.String(), id, deliveredAt, nextRunAt)
	if err != nil {
		return mapWriteErr("dashboard report schedule", err)
	}
	if tag.RowsAffected() == 0 {
		return notFound("dashboard report schedule", pgx.ErrNoRows)
	}
	return nil
}

const reportArtifactColumns = `id, tenant_id::text, dashboard_id, schedule_id, format,
 media_type, filename, content, generated_by, generated_at, absolute_from, absolute_to,
 provenance, redaction_state, coverage_limitations`

func scanReportArtifact(row interface{ Scan(...any) error }, out *ReportArtifact) error {
	var provenance, limitations []byte
	if err := row.Scan(&out.ID, &out.TenantID, &out.DashboardID, &out.ScheduleID,
		&out.Format, &out.MediaType, &out.Filename, &out.Content, &out.GeneratedBy,
		&out.GeneratedAt, &out.AbsoluteFrom, &out.AbsoluteTo, &provenance,
		&out.RedactionState, &limitations); err != nil {
		return notFound("dashboard report artifact", err)
	}
	out.Provenance = append(out.Provenance[:0], provenance...)
	out.CoverageLimitations = append(out.CoverageLimitations[:0], limitations...)
	return nil
}

func (DashboardReports) CreateArtifact(ctx context.Context, s tenancy.Scope, in ReportArtifactInput) (*ReportArtifact, error) {
	provenance, err := json.Marshal(in.Provenance)
	if err != nil {
		return nil, err
	}
	limitations, err := json.Marshal(in.CoverageLimitations)
	if err != nil {
		return nil, err
	}
	var out ReportArtifact
	err = scanReportArtifact(s.Q.QueryRow(ctx, `
		INSERT INTO dashboard_report_artifacts
		       (tenant_id, id, dashboard_id, schedule_id, format, media_type, filename,
		        content, generated_by, absolute_from, absolute_to, provenance,
		        redaction_state, coverage_limitations)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14::jsonb)
		RETURNING `+reportArtifactColumns,
		s.Tenant.String(), in.ID, in.DashboardID, in.ScheduleID, in.Format,
		in.MediaType, in.Filename, in.Content, in.GeneratedBy, in.AbsoluteFrom,
		in.AbsoluteTo, provenance, in.RedactionState, limitations), &out)
	if err != nil {
		return nil, mapWriteErr("dashboard report artifact", err)
	}
	return &out, nil
}

// GetArtifact applies the saved view's owner/shared visibility inside the
// tenant boundary. A private artifact guessed by another same-tenant user is
// indistinguishable from a missing or cross-tenant id.
func (DashboardReports) GetArtifact(ctx context.Context, s tenancy.Scope, id, userID string) (*ReportArtifact, error) {
	var out ReportArtifact
	err := scanReportArtifact(s.Q.QueryRow(ctx, `
		SELECT a.id, a.tenant_id::text, a.dashboard_id, a.schedule_id, a.format,
		       a.media_type, a.filename, a.content, a.generated_by, a.generated_at,
		       a.absolute_from, a.absolute_to, a.provenance, a.redaction_state,
		       a.coverage_limitations
		  FROM dashboard_report_artifacts a
		  JOIN dashboard_views v
		    ON v.tenant_id = a.tenant_id AND v.id = a.dashboard_id
		 WHERE a.tenant_id = $1 AND a.id = $2 AND (v.owner_id = $3 OR v.shared)`,
		s.Tenant.String(), id, userID), &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (DashboardReports) ListArtifacts(ctx context.Context, s tenancy.Scope, userID string) ([]ReportArtifact, error) {
	rows, err := s.Q.Query(ctx, `
		SELECT a.id, a.tenant_id::text, a.dashboard_id, a.schedule_id, a.format,
		       a.media_type, a.filename, NULL::bytea, a.generated_by, a.generated_at,
		       a.absolute_from, a.absolute_to, a.provenance, a.redaction_state,
		       a.coverage_limitations
		  FROM dashboard_report_artifacts a
		  JOIN dashboard_views v
		    ON v.tenant_id = a.tenant_id AND v.id = a.dashboard_id
		 WHERE a.tenant_id = $1 AND (v.owner_id = $2 OR v.shared)
		 ORDER BY a.generated_at DESC, a.id LIMIT 200`, s.Tenant.String(), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportArtifact{}
	for rows.Next() {
		var item ReportArtifact
		if err := scanReportArtifact(rows, &item); err != nil {
			return nil, err
		}
		item.Content = nil // list metadata only; download is an explicit audited read
		out = append(out, item)
	}
	return out, rows.Err()
}
