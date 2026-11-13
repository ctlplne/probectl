// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func cleanClientReportDefinition(d *dashboardDefinition) error {
	if d.ClientReport == nil {
		return nil
	}
	if d.ClientReport.CapacityTargets == nil {
		d.ClientReport.CapacityTargets = []reporting.ClientReportCapacityTarget{}
	}
	if len(d.FlowSources) != 0 || !d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.IsZero() || len(d.Metrics) != 0 {
		return apierror.Validation("client_report derives its complete monthly bounds and values; omit flow_sources, absolute bounds and metrics")
	}
	period, err := reporting.ResolveClientReportPeriod(context.Background(), *d.ClientReport, time.Now().UTC())
	from, to := period.From, period.To
	if err != nil {
		return apierror.Validation("client_report requires a valid timezone and completed month or current month-to-date period")
	}
	for _, target := range d.ClientReport.CapacityTargets {
		if _, err := clientReportCapacityInput(target, from, to, period.Timezone); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) captureConfiguredReportSources(ctx context.Context, actor *auth.Principal, definition dashboardDefinition, at time.Time) (*reportFlowCapture, error) {
	if definition.ClientReport == nil {
		return s.captureReportFlowSources(ctx, actor, definition.FlowSources)
	}
	capture, err := s.captureConfiguredClientReportSources(ctx, actor, *definition.ClientReport, at, flowstore.ExplorerQueryBudget(s.flowStore))
	if err != nil {
		return nil, err
	}
	requirements, err := clientReportRequirements(capture)
	if err != nil {
		capture.close()
		return nil, err
	}
	return &reportFlowCapture{TenantID: capture.TenantID, SourceGeneration: capture.SourceGeneration, Monthly: requirements, Tables: redactMonthlyReportTables(capture.Tables, redactionPolicy(s.cfg), actor.TenantID), monthlyCapture: capture, release: capture.close}, nil
}

func revalidateMonthlyReportOriginals(ctx context.Context, capture *reportFlowCapture) error {
	if capture.Monthly == nil {
		return nil
	}
	original := capture.monthlyCapture
	if original == nil {
		return errReportSourceRequirements
	}
	if err := original.testsPublication(ctx); err != nil {
		return err
	}
	for _, verdict := range original.Verdicts {
		if err := verdict.publication(ctx); err != nil {
			return err
		}
	}
	for _, capacity := range original.Capacity {
		if err := capacity.publication(ctx); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Only display/source-description cells are redacted. Canonical counts,
// digests, contracts and the complete signed offline envelope stay exact.
func redactMonthlyReportTables(tables []reporting.CSVTable, policy ai.RedactionPolicy, tenant string) []reporting.CSVTable {
	out := append([]reporting.CSVTable{}, tables...)
	text := map[string]bool{"name": true, "display_name": true, "service": true, "title": true, "target": true, "prefix": true, "actor": true, "hypotheses": true, "all_hypotheses": true, "summary": true, "ref": true, "url": true, "attributes": true, "config_predecessors": true, "query_and_explicit_assumptions": true}
	for i := range out {
		original := out[i].WalkRows
		columns := out[i].Columns
		out[i].WalkRows = func(ctx context.Context, visit func([]string) error) error {
			return original(ctx, func(row []string) error {
				clean := append([]string{}, row...)
				for index, column := range columns {
					if index < len(clean) && text[column.Name] {
						clean[index] = ai.RedactTextForTenant(clean[index], policy, tenant)
					}
				}
				return visit(clean)
			})
		}
	}
	return out
}
