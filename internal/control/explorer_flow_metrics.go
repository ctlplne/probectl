// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/metrics"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type flowOperationMetrics struct {
	outcomes map[string]*metrics.Counter
	active   atomic.Int64
	duration *metrics.Histogram
}

func (s *Server) registerFlowQueryMetrics() {
	s.flowOperationMetrics = make(map[string]*flowOperationMetrics)
	for _, operation := range otel.FlowExplorerOperations() {
		names, ok := otel.FlowExplorerMetrics(operation)
		if !ok {
			continue
		}
		prom := func(name string) string { return strings.ReplaceAll(name, ".", "_") }
		m := &flowOperationMetrics{outcomes: s.metrics.LabeledCounter(prom(names.Operations)+"_total", "Completed native flow service operations by fixed outcome; no tenant or query labels.", "outcome", otel.FlowExplorerOutcomes())}
		histogram, err := s.metrics.Histogram(prom(names.Duration)+"_seconds", "Native flow service duration in seconds; includes failures, no tenant or query labels.", otel.FlowExplorerDurationBuckets())
		if err != nil {
			// Instrumentation health never changes service/audit behavior.
			s.log.Error("native flow service duration histogram unavailable")
		}
		m.duration = histogram
		s.metrics.Gauge(prom(names.Active), "Active native flow service operations on this replica; no tenant labels.", func() float64 { return float64(m.active.Load()) })
		s.flowOperationMetrics[operation] = m
	}
}

func (s *Server) beginFlowOperation(ctx context.Context, operation string) func(error) {
	m := s.flowOperationMetrics[operation]
	if m == nil {
		return func(error) {}
	}
	started := time.Now()
	m.active.Add(1)
	var once sync.Once
	return func(err error) {
		once.Do(func() {
			if err != nil && ctx.Err() != nil {
				err = ctx.Err()
			}
			m.outcomes[flowOperationOutcome(err)].Inc()
			m.duration.Observe(time.Since(started).Seconds())
			m.active.Add(-1)
		})
	}
}

func flowOperationOutcome(err error) string {
	if err == nil {
		return "success"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, flowstore.ErrExplorerBudget) || errors.Is(err, flowsnapshot.ErrBudget) {
		return "budget"
	}
	var domain *apierror.Error
	if errors.As(err, &domain) {
		switch apierror.Code(domain.Code) {
		case apierror.CodeFlowQueryBudget, apierror.CodeQuotaExceeded, apierror.CodeTooLarge:
			return "budget"
		case apierror.CodeFlowQueryCoverage:
			return "coverage"
		case apierror.CodeValidation, apierror.CodeBadRequest, apierror.CodeNotFound, apierror.CodeConflict:
			return "validation"
		case apierror.CodeUnauthorized, apierror.CodeForbidden, apierror.CodeTenantSuspended, apierror.CodeTenantOffboarded, apierror.CodeTenantQuarantined:
			return "authorization"
		}
	}
	return "unavailable"
}
