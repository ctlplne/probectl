// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func (s *Server) recordSeasonalFlowWindows(ctx context.Context, tenant string, latest flow.QueryPlan, ends []time.Time, topKeys int, source preparedReportFlow) ([]flowstore.PlanResult, error) {
	batch, present := ctx.Value(reportFlowBatchKey{}).(*flowstore.PlanBatch)
	if !present || batch == nil || len(ends) == 0 || !latest.To.Equal(ends[len(ends)-1]) || !latest.From.Before(latest.To) {
		return nil, apierror.Unavailable("seasonal flow query requires a complete admitted window batch")
	}
	tagData, err := flowTagQueryFromContext(ctx, tenant)
	if err != nil {
		return nil, err
	}
	query := flowstore.PlanQuery{TenantID: tenant, Plan: latest, Tags: tagData,
		DDoSProjection: source.ddosSourcePortProjection, DDoSVerifySampling: source.ddosVerifySampling}
	span := latest
	span.From = ends[0].Add(-latest.To.Sub(latest.From))
	authority, err := s.bindFlowPlanProjections(ctx, &query, span)
	if err != nil {
		return nil, err
	}
	results, err := batch.ExploreSeasonalWindows(query, ends, topKeys)
	if err != nil {
		return nil, flowExplorerStoreError(err)
	}
	if len(results) != len(ends) {
		return nil, apierror.Unavailable("seasonal flow query returned incomplete clocks")
	}
	for i, result := range results {
		if !result.Query.To.Equal(ends[i]) || result.RoleTenantID != results[0].RoleTenantID ||
			result.RoleDigest != results[0].RoleDigest || result.RoutingProof != results[0].RoutingProof {
			return nil, apierror.Unavailable("seasonal flow windows disagree about current captured metadata")
		}
	}
	if err := s.checkFlowPlanProjections(ctx, tenant, span, &results[0], authority); err != nil {
		return nil, err
	}
	return results, ctx.Err()
}
