// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type providerReportQueue struct{ server *Server }

const (
	providerMonthlyReportKind    = "monthly"
	providerComplianceReportKind = "compliance"
)

// MonthlyReportQueue is attached only by the licensed provider build seam.
// Tenant consent controls are available when that actual service is attached;
// core never imports or checks a commercial edition.
func (s *Server) MonthlyReportQueue() reporting.MonthlyReportQueue {
	if s == nil || s.pool == nil || s.fairnessGate == nil {
		return nil
	}
	s.providerReportTriggers = true
	return providerReportQueue{server: s}
}

// The queue changes schedule metadata under tenant RLS and its audit lock. It
// filters by report-family markers and returns counts. The worker separately
// resolves current owner authority and source grants without MFA delegation.
func (q providerReportQueue) QueueMonthlyReports(ctx context.Context, tenant, operator, requestID string) (reporting.MonthlyReportQueueResult, error) {
	return q.tenantReports(ctx, tenant, operator, requestID, providerMonthlyReportKind, true)
}

func (q providerReportQueue) MonthlyReportProgress(ctx context.Context, tenant, operator, requestID string) (reporting.MonthlyReportQueueResult, error) {
	return q.tenantReports(ctx, tenant, operator, requestID, providerMonthlyReportKind, false)
}

// ComplianceReportQueue is attached only by the same licensed provider seam.
func (s *Server) ComplianceReportQueue() reporting.ComplianceReportQueue {
	if s == nil || s.pool == nil || s.fairnessGate == nil {
		return nil
	}
	s.providerReportTriggers = true
	return providerReportQueue{server: s}
}

func (q providerReportQueue) QueueComplianceReports(ctx context.Context, tenant, operator, requestID string) (reporting.ProviderReportQueueResult, error) {
	return q.tenantReports(ctx, tenant, operator, requestID, providerComplianceReportKind, true)
}

func (q providerReportQueue) ComplianceReportProgress(ctx context.Context, tenant, operator, requestID string) (reporting.ProviderReportQueueResult, error) {
	return q.tenantReports(ctx, tenant, operator, requestID, providerComplianceReportKind, false)
}

func (q providerReportQueue) tenantReports(ctx context.Context, tenant, operator, requestID, kind string, create bool) (reporting.ProviderReportQueueResult, error) {
	none := reporting.ProviderReportQueueResult{}
	if !reportRequirementUUID(tenant) || !reportRequirementUUID(requestID) || strings.TrimSpace(operator) == "" {
		return none, apierror.Validation("canonical tenant/request IDs and provider attribution are required")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenant {
		return none, entity.ErrScopeMismatch
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	s := q.server
	if err := s.currentReportTenant(ctx, tenant); err != nil {
		return none, err
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return none, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	release, err := s.fairnessGate.BeginQuery(ctx, tenant)
	if err != nil {
		return none, err
	}
	defer release()
	result := reporting.ProviderReportQueueResult{TenantID: tenant}
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		var raw []byte
		err := sc.Q.QueryRow(ctx, `SELECT data FROM audit_events WHERE tenant_id=$1 AND action='dashboard.provider_report_request' AND target=$2 ORDER BY seq LIMIT 1`, tenant, requestID).Scan(&raw)
		if err == nil {
			var prior struct {
				Operator string                              `json:"operator"`
				Kind     string                              `json:"kind"`
				Result   reporting.ProviderReportQueueResult `json:"result"`
			}
			if err := json.Unmarshal(raw, &prior); err != nil {
				return err
			}
			if prior.Kind == "" {
				prior.Kind = providerMonthlyReportKind
			}
			if prior.Operator != operator || prior.Result.TenantID != tenant || prior.Kind != kind {
				return apierror.Forbidden("provider report request attribution changed")
			}
			result = prior.Result
			result.Replay = true
			return reportQueueProgress(ctx, sc, requestID, &result)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if !create {
			return apierror.NotFound("provider report request not found")
		}
		return queueProviderReportSchedules(ctx, sc, requestID, operator, kind, &result)
	})
	if err != nil {
		return none, err
	}
	return result, nil
}

func queueProviderReportSchedules(ctx context.Context, sc tenancy.Scope, requestID, operator, kind string, result *reporting.ProviderReportQueueResult) error {
	tenant := sc.Tenant.String()
	err := sc.Q.QueryRow(ctx, `WITH eligible AS MATERIALIZED (
 SELECT s.id FROM dashboard_report_schedules s JOIN dashboard_views v
 ON (v.tenant_id,v.id)=(s.tenant_id,s.dashboard_id)
 WHERE s.tenant_id=$1 AND v.tenant_id=$1 AND s.enabled AND s.provider_trigger_allowed
 AND (v.owner_id=s.owner_id OR v.shared)
 AND (($3::text='monthly' AND jsonb_typeof(v.definition->'client_report')='object')
   OR ($3::text='compliance' AND v.definition->>'compliance_control'=ANY($4::text[])))),
 queued AS (UPDATE dashboard_report_schedules s SET provider_request_id=$2::uuid,
 provider_original_next_run_at=s.next_run_at,next_run_at=transaction_timestamp(),updated_at=clock_timestamp()
 FROM eligible e WHERE s.tenant_id=$1 AND s.id=e.id AND s.next_run_at>transaction_timestamp()
 AND s.provider_request_id IS NULL RETURNING s.id)
 SELECT (SELECT count(*) FROM eligible),(SELECT count(*) FROM queued)`, tenant, requestID, kind, compliance.ControlEvidenceReferences()).Scan(&result.Eligible, &result.Queued)
	if err != nil {
		return err
	}
	if err := reportQueueProgress(ctx, sc, requestID, result); err != nil {
		return err
	}
	_, err = audit.TenantAppend(ctx, sc, "provider-report-trigger", "dashboard.provider_report_request", requestID, map[string]any{"operator": operator, "kind": kind, "result": result})
	return err
}

func reportQueueProgress(ctx context.Context, sc tenancy.Scope, requestID string, result *reporting.ProviderReportQueueResult) error {
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_schedules WHERE tenant_id=$1 AND provider_request_id=$2::uuid AND enabled AND provider_trigger_allowed`, sc.Tenant.String(), requestID).Scan(&result.Pending); err != nil {
		return err
	}
	if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='dashboard.report_delivery' AND data->>'provider_request_id'=$2`, sc.Tenant.String(), requestID).Scan(&result.Delivered); err != nil {
		return err
	}
	result.Inactive = result.Queued - result.Pending - result.Delivered
	if result.Inactive < 0 {
		return apierror.Unavailable("provider report progress is inconsistent")
	}
	return nil
}
