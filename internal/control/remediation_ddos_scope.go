// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/anomaly"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// verifyPrefixImpactDetector intersects the exact original selection with the
// authorized senders. The same four windows must account for the entire cited
// observation population, including the two reference windows.
func (s *Server) verifyPrefixImpactDetector(ctx context.Context, actor *auth.Principal, ruleID string, original alert.DDoSEvaluationEvidence,
	origins []store.PrefixImpactFlowBinding, budget flowstore.ExplorerBudget) error {
	release, err := s.fairnessGate.BeginQuery(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	defer release()
	capture, err := s.captureMatchedDDoSOrigins(ctx, actor, ruleID, original, origins, budget)
	if err != nil {
		return err
	}
	defer capture.Close()
	return s.recheckFlowEvidencePublication(ctx, actor, capture)
}

func (s *Server) captureMatchedDDoSOrigins(ctx context.Context, actor *auth.Principal, ruleID string, original alert.DDoSEvaluationEvidence,
	origins []store.PrefixImpactFlowBinding, budget flowstore.ExplorerBudget) (_ *reportFlowCapture, resultErr error) {
	settings, err := s.citedDDoSSettings(ctx, ruleID, original, budget.MemoryBytes/8)
	if err != nil {
		return nil, err
	}
	clocks, err := ddosClocks(original.Current.After.To, settings.Input.PeriodSeconds)
	if err != nil {
		return nil, err
	}
	settings.Origins = origins
	capture, err := s.captureDDoSWindows(ctx, actor, settings, clocks.ends(), budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			capture.Close()
		}
	}()
	for _, window := range []struct {
		expected      flow.DDoSAssessment
		clocks        anomaly.FlowFieldComparisonClocks
		before, after int
	}{
		{original.Previous, clocks.Previous, 0, 2},
		{original.Current, clocks.Current, 1, 3},
	} {
		measured, err := assessCapturedDDoS(ctx, capture, settings, window.clocks, window.before, window.after, budget.MemoryBytes/8)
		if err != nil {
			return nil, mapDDoSCoverage(err)
		}
		if !sameDDoSRoutingEvidence(window.expected, measured) {
			return nil, apierror.Conflict("the original traffic receipt does not fit the selected routing context")
		}
	}
	capture.Results = nil
	return capture, ctx.Err()
}

func (s *Server) citedDDoSSettings(ctx context.Context, ruleID string, evidence alert.DDoSEvaluationEvidence, memory int64) (ddosAssessmentSettings, error) {
	var out ddosAssessmentSettings
	err := tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rules := store.AlertRules{}
		rule, err := rules.Get(ctx, sc, ruleID)
		if err != nil {
			return err
		}
		source, err := rules.GetQuerySource(ctx, sc, ruleID, rule.UpdatedAt, memory)
		if err != nil {
			return err
		}
		if source == nil || source.Source.Condition.Mode != alert.DDoSCondition || source.Source.Condition.DDoS == nil ||
			source.Source.ViewID != evidence.Current.ViewID || source.Source.ViewVersion != evidence.Current.Version {
			return apierror.Conflict("the detector revision changed during routing review")
		}
		out, err = normalizeDDoSAssessment(source.Source.ViewID, *source.Source.Condition.DDoS)
		return err
	})
	return out, err
}

func sameDDoSRoutingEvidence(cited, measured flow.DDoSAssessment) bool {
	return cited.ViewID == measured.ViewID && cited.Version == measured.Version && cited.Prefix == measured.Prefix &&
		cited.Direction == measured.Direction && sameDDoSRoutingWindow(cited.Before, measured.Before) && sameDDoSRoutingWindow(cited.After, measured.After) &&
		cited.Detection != nil && measured.Detection != nil && *cited.Detection == *measured.Detection
}

func sameDDoSRoutingWindow(cited, measured flow.DDoSWindowEvidence) bool {
	if !cited.From.Equal(measured.From) || !cited.To.Equal(measured.To) {
		return false
	}
	measured.From, measured.To = cited.From, cited.To
	return cited == measured
}
