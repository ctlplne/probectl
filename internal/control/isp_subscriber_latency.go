// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type subscriberLatencyCapture struct {
	tests  []store.IncidentConfiguredTest
	reads  []store.IncidentTestMeasurement
	memory int64
}

func (s *Server) captureSubscriberLatency(ctx context.Context, actor *auth.Principal, contexts []string, input flow.SubscriberUsageRequest,
	from, to time.Time, memory int64) ([]flow.SubscriberLatency, *subscriberLatencyCapture, error) {
	capture := &subscriberLatencyCapture{memory: memory}
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorizeClientReportTests(ctx, principal, map[string]string{auth.ResourceTenantKey: sc.Tenant.String()}); err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
			if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["test_id"] = member.EntityID, testID
			return s.authorizeClientReportTests(ctx, principal, resource)
		}
		capture.tests, err = store.SubscriberTestsInScope(ctx, sc, contexts, input.TagID, input.Subscriber, capture.memory, authorize)
		if err != nil || len(capture.tests) == 0 {
			return err
		}
		capture.reads, err = (store.Incidents{}).IncidentWindowTestMeasurementsInScope(ctx, sc, capture.tests, from.Truncate(time.Microsecond), to, capture.memory)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	values, err := summarizeOriginalTestPeriods(ctx, actor.TenantID, capture.tests, capture.reads, []originalMeasurementWindow{{from, to}}, capture.memory)
	if err != nil {
		return nil, nil, err
	}
	out := make([]flow.SubscriberLatency, 0, len(values))
	for _, value := range values {
		period := value.periods[0]
		row := flow.SubscriberLatency{ContextID: value.source.ContextID, EntityID: value.source.EntityID,
			AgentID: value.source.AgentID, TestID: value.source.TestID,
			Test: value.source.Name, Target: value.source.Target, Coverage: period.LatencyCoverage}
		if latency := period.Latency; latency != nil {
			row.Samples, row.SumNanos = latency.Samples, latency.SumNanos
			row.MinimumNanos, row.MaximumNanos, row.MeanNanos = latency.MinimumNanos, latency.MaximumNanos, latency.MeanNanos
		}
		out = append(out, row)
	}
	return out, capture, ctx.Err()
}

func (s *Server) verifySubscriberLatency(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, capture *subscriberLatencyCapture) error {
	if capture == nil {
		return nil
	}
	if err := s.revalidateClientReportTestsInScope(ctx, sc, actor, capture.tests, capture.memory); err != nil {
		return err
	}
	return (store.Incidents{}).RecheckIncidentTestMeasurementsInScope(ctx, sc, capture.reads, capture.memory)
}
