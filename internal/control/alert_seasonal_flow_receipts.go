// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The alert receipt always has a generic state. Exact values and citations
// are projected only when the current reader can reproduce the original scope.
// A native result repeats this check at its final serialization boundary.
func (s *Server) prepareSeasonalFlowReceiptPublication(ctx context.Context, actor *auth.Principal, ruleID string, items []alert.EvaluationReceipt, credential func(context.Context) error, retain pathHealthPublication) error {
	var exact []*alert.EvaluationReceipt
	for i := range items {
		item := &items[i]
		if evidence := item.Expectation.Seasonal; evidence != nil && (evidence.Exact != nil || len(evidence.FlowScope) > 0) {
			exact = append(exact, item)
		}
	}
	if len(exact) == 0 {
		return nil
	}
	check := func(ctx context.Context, redact bool) error {
		if credential == nil {
			return alert.ErrSeasonalSource
		}
		if err := credential(ctx); err != nil {
			return err
		}
		if err := s.recheckSeasonalFlowReceipts(ctx, actor, ruleID, exact, redact); err != nil {
			return err
		}
		return credential(ctx)
	}
	if err := check(ctx, true); err != nil {
		for _, item := range exact {
			redactSeasonalFlowReceipt(item)
		}
		return nil
	}
	if retain == nil {
		return nil
	}
	for _, item := range exact {
		if item.Expectation.Seasonal != nil {
			return retain(ctx, func(ctx context.Context) error { return check(ctx, false) }, func() {})
		}
	}
	return nil
}

func redactSeasonalFlowReceipt(item *alert.EvaluationReceipt) {
	item.ObservedValue = nil
	item.Expectation.Seasonal = nil
}

func (s *Server) recheckSeasonalFlowReceipts(ctx context.Context, actor *auth.Principal, ruleID string, items []*alert.EvaluationReceipt, redact bool) error {
	ctx, _, err := s.alertQueryRequest(ctx, actor, permAlertRead)
	if err != nil {
		return err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, min(5*time.Second, budget.ExecutionLimit))
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	return tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rules := store.AlertRules{}
		rule, err := rules.Get(ctx, sc, ruleID)
		if err != nil || rule.Metric != alert.SeasonalFlowMetric {
			return alert.ErrSeasonalSource
		}
		return rules.WithSeasonalPublication(ctx, sc, ruleID, rule.UpdatedAt, budget.MemoryBytes/8,
			func(ctx context.Context, sc tenancy.Scope, src *alert.SeasonalSource) error {
				if src.Config.Flow == nil {
					return alert.ErrSeasonalSource
				}
				if err := s.authorizeSeasonalPublication(ctx, sc, src); err != nil {
					return err
				}
				return s.recheckSeasonalFlowReceiptItems(store.WithReportSourceAuditLock(ctx, sc), sc, actor, *rule, src.Config, items, budget.MemoryBytes/8, redact)
			})
	})
}

func (s *Server) recheckSeasonalFlowReceiptItems(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, rule alert.Rule, config alert.SeasonalBaselineInput, items []*alert.EvaluationReceipt, memory int64, redact bool) error {
	checked := make(map[string]time.Time)
	revision := rule.UpdatedAt.UTC().Format(time.RFC3339Nano)
	for _, item := range items {
		evidence := item.Expectation.Seasonal
		if evidence == nil && !redact {
			continue // the first response projection already withheld this row
		}
		err := alert.ErrSeasonalSource
		if evidence != nil && evidence.Exact != nil && item.RuleID == rule.ID && item.RuleRevision == revision {
			key := string(crypto.Hash(evidence.FlowScope))
			if len(key) == 32 && checked[key].Equal(evidence.ObservedAt) && !evidence.ObservedAt.IsZero() {
				err = nil
			} else {
				capture, decodeErr := decodeSeasonalFlowScope(ctx, evidence.FlowScope, config, evidence.ObservedAt, memory)
				if decodeErr == nil {
					err = s.validateReportSourcePublication(ctx, sc, actor, capture)
					if err == nil && len(key) == 32 {
						checked[key] = evidence.ObservedAt
					}
				}
			}
		}
		if err != nil {
			if !redact {
				return err
			}
			redactSeasonalFlowReceipt(item)
		}
	}
	return ctx.Err()
}
