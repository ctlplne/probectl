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
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type monthlyReportQueue struct{ server *Server }

// MonthlyReportQueue is attached only by the licensed provider build seam.
// Tenant consent controls are available when that actual service is attached;
// core never imports or checks a commercial edition.
func (s *Server) MonthlyReportQueue() reporting.MonthlyReportQueue {
	if s == nil || s.pool == nil || s.fairnessGate == nil {
		return nil
	}
	s.providerReportTriggers = true
	return monthlyReportQueue{server: s}
}

// QueueMonthlyReports changes schedule metadata under tenant RLS and its audit
// lock. Only schedule metadata and the monthly definition-kind marker are read;
// no source facts or report bodies are returned. The existing worker later
// resolves current owner authority and source grants without MFA delegation.
func (q monthlyReportQueue) QueueMonthlyReports(ctx context.Context, tenant, operator, requestID string) (reporting.MonthlyReportQueueResult, error) {
	return q.monthlyReports(ctx, tenant, operator, requestID, true)
}

func (q monthlyReportQueue) MonthlyReportProgress(ctx context.Context, tenant, operator, requestID string) (reporting.MonthlyReportQueueResult, error) {
	return q.monthlyReports(ctx, tenant, operator, requestID, false)
}

func (q monthlyReportQueue) monthlyReports(ctx context.Context, tenant, operator, requestID string, create bool) (reporting.MonthlyReportQueueResult, error) {
	none := reporting.MonthlyReportQueueResult{}
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
	result := reporting.MonthlyReportQueueResult{TenantID: tenant}
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, tenant); err != nil {
			return err
		}
		var raw []byte
		err := sc.Q.QueryRow(ctx, `SELECT data FROM audit_events WHERE tenant_id=$1 AND action='dashboard.provider_report_request' AND target=$2 ORDER BY seq LIMIT 1`, tenant, requestID).Scan(&raw)
		if err == nil {
			var prior struct {
				Operator string                             `json:"operator"`
				Result   reporting.MonthlyReportQueueResult `json:"result"`
			}
			if err := json.Unmarshal(raw, &prior); err != nil {
				return err
			}
			if prior.Operator != operator || prior.Result.TenantID != tenant {
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
		err = sc.Q.QueryRow(ctx, `WITH eligible AS MATERIALIZED (
 SELECT s.id FROM dashboard_report_schedules s JOIN dashboard_views v
 ON (v.tenant_id,v.id)=(s.tenant_id,s.dashboard_id)
 WHERE s.tenant_id=$1 AND v.tenant_id=$1 AND s.enabled AND s.provider_trigger_allowed
 AND (v.owner_id=s.owner_id OR v.shared) AND jsonb_typeof(v.definition->'client_report')='object'),
 queued AS (UPDATE dashboard_report_schedules s SET provider_request_id=$2::uuid,
 provider_original_next_run_at=s.next_run_at,next_run_at=transaction_timestamp(),updated_at=clock_timestamp()
 FROM eligible e WHERE s.tenant_id=$1 AND s.id=e.id AND s.next_run_at>transaction_timestamp()
 AND s.provider_request_id IS NULL RETURNING s.id)
 SELECT (SELECT count(*) FROM eligible),(SELECT count(*) FROM queued)`, tenant, requestID).Scan(&result.Eligible, &result.Queued)
		if err != nil {
			return err
		}
		if err := reportQueueProgress(ctx, sc, requestID, &result); err != nil {
			return err
		}
		_, err = audit.TenantAppend(ctx, sc, "provider-report-trigger", "dashboard.provider_report_request", requestID, map[string]any{"operator": operator, "result": result})
		return err
	})
	if err != nil {
		return none, err
	}
	return result, nil
}

func reportQueueProgress(ctx context.Context, sc tenancy.Scope, requestID string, result *reporting.MonthlyReportQueueResult) error {
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
