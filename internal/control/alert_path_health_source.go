// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) loadAlertPathHealthSource(ctx context.Context, rule alert.Rule, memory int64) (*alert.PathHealthSource, error) {
	var source *alert.PathHealthSource
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		source, err = (store.AlertRules{}).GetPathHealthSource(ctx, sc, rule.ID, rule.UpdatedAt, memory)
		return err
	})
	if err == nil && source == nil {
		err = store.ErrAlertPathHealthChanged
	}
	return source, err
}

func (s *Server) readAlertPathHealthRule(ctx context.Context, tenant string, rule alert.Rule) (alert.RuleMetricRead, error) {
	if s.pool == nil || s.fairnessGate == nil || tenant == "" || tenant != rule.TenantID || rule.Metric != alert.PathHealthMetric {
		return alert.RuleMetricRead{}, apierror.Unavailable("current path alert source is unavailable")
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenant {
		return alert.RuleMetricRead{}, tenancy.ErrNoTenant
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if budget.Validate() != nil {
		return alert.RuleMetricRead{}, apierror.Unavailable("path alert source admission is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	// One slot covers bounded configuration transfer and the delegated read.
	release, err := s.fairnessGate.BeginQuery(ctx, tenant)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	defer release()
	source, err := s.loadAlertPathHealthSource(ctx, rule, budget.MemoryBytes/8)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	actor, err := source.CredentialCeiling(tenant)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	ctx, err = bindFlowRoleContext(ctx, actor)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	current, err := loadCurrentUserAuthority(ctx, s.pool, tenant, actor.UserID)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	ctx, _, err = current.requestContext(ctx, actor)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	// Retain the stored read ceiling, not the current user's wider roles.
	ctx = auth.WithPrincipal(ctx, auth.ClonePrincipal(actor))
	to := time.Now().UTC()
	values := url.Values{"health_from": {to.Add(-time.Duration(source.LookbackSeconds) * time.Second).Format(time.RFC3339Nano)},
		"health_to": {to.Format(time.RFC3339Nano)}, "health_poll_gap": {strconv.FormatInt(source.PollGapSeconds, 10) + "s"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "/v1/tests/"+source.TestID+"/path/entities?"+values.Encode(), nil)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	request.SetPathValue("id", source.TestID)
	options, err := parsePathHealthOptions(request, to)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	// Follow the existing saved-query alert source: an internal scheduled read
	// uses its retained ceiling and current grants, never a reconstructed bearer
	// or MFA assertion. Interactive ingress keeps its existing MFA checks.
	query := &pathHealthOperation{op: capacityForecastOperation{request: request, actor: actor, budget: budget},
		options: options, remaining: budget.MemoryBytes - budget.MemoryBytes/4}
	snapshot, err := s.readPathHealth(query)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	result, err := pathHealthAlertSelection(query, snapshot, rule, *source)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	// A reconfiguration, withdrawn user/source grant or changed path refuses
	// the complete decision. No old credential or stale gauge is substituted.
	latest, err := s.loadAlertPathHealthSource(ctx, rule, query.op.budget.MemoryBytes/8)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	before, err := source.Binding(tenant, rule.ID)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	after, err := latest.Binding(tenant, rule.ID)
	if err != nil || before != after {
		return alert.RuleMetricRead{}, store.ErrAlertPathHealthChanged
	}
	if err := s.revalidatePathHealthSnapshot(query, snapshot); err != nil {
		return alert.RuleMetricRead{}, err
	}
	// This scheduled operation has no originating HTTP credential. The complete
	// snapshot check above re-reads the retained owner's current grants and all
	// source identities; it never reconstructs a bearer or an MFA assertion.
	return result, ctx.Err()
}

func pathHealthAlertSelection(query *pathHealthOperation, snapshot pathHealthSnapshot, rule alert.Rule, source alert.PathHealthSource) (alert.RuleMetricRead, error) {
	if query == nil || query.op.actor == nil || query.op.actor.TenantID != rule.TenantID || query.op.actor.UserID != source.OwnerUserID || snapshot.result.TestID != source.TestID {
		return alert.RuleMetricRead{}, alert.ErrPathHealthSource
	}
	binding, err := source.Binding(rule.TenantID, rule.ID)
	if err != nil {
		return alert.RuleMetricRead{}, err
	}
	held := alert.RuleMetricRead{Skip: true}
	if snapshot.result.Status != "current" {
		return held, nil
	}
	var selected *pathHealthErrorTrend
	for _, hop := range snapshot.result.Items {
		if hop.Health == nil || hop.Health.InterfaceID != source.InterfaceID {
			continue
		}
		for i := range hop.Health.ErrorTrends {
			trend := &hop.Health.ErrorTrends[i]
			if trend.Metric != source.Metric {
				continue
			}
			if selected != nil {
				first, err := json.Marshal(selected)
				if err != nil {
					return alert.RuleMetricRead{}, err
				}
				next, err := json.Marshal(trend)
				if err != nil || !bytes.Equal(first, next) {
					return alert.RuleMetricRead{}, apierror.Unavailable("ambiguous original port baseline")
				}
			}
			selected = trend
		}
	}
	if selected == nil || selected.BaselineSamples < 3 || len(selected.Observations) < 4 {
		return held, nil
	}
	value := 0.0
	switch selected.State {
	case "rising_minimum_rate":
		value = 1
	case "within_baseline", "below_baseline":
	default:
		return held, nil
	}
	var provenance []byte
	for _, check := range query.checks {
		if check.target.InterfaceID != source.InterfaceID {
			continue
		}
		encoded, err := json.Marshal(struct {
			Binding string
			Source  flowstore.CounterSource
			IfIndex uint32
		}{binding, check.target.Source, check.target.IfIndex})
		if err != nil {
			return alert.RuleMetricRead{}, err
		}
		if provenance != nil && !bytes.Equal(provenance, encoded) {
			return alert.RuleMetricRead{}, apierror.Unavailable("ambiguous current port source")
		}
		provenance = encoded
	}
	if provenance == nil {
		return held, nil
	}
	group := hex.EncodeToString(crypto.Hash(provenance))
	return alert.RuleMetricRead{Samples: []alert.Sample{{Labels: map[string]string{"path_test_id": source.TestID, "path_health_group": group}, Value: value}},
		QuerySelection: &alert.QuerySelection{TenantID: rule.TenantID, RuleID: rule.ID, Binding: binding, At: query.options.to, Complete: true}}, nil
}
