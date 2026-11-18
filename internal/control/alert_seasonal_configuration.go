// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type alertSeasonalState = alert.SeasonalSourceState

func (s *Server) handleGetAlertSeasonalSource(w http.ResponseWriter, r *http.Request) error {
	actor := auth.PrincipalFrom(r.Context())
	state, err := s.getAlertSeasonalSource(r.Context(), actor, r.PathValue("id"), s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return alertSeasonalError(err)
	}
	writeJSON(w, http.StatusOK, state)
	return nil
}

func (s *Server) handlePutAlertSeasonalSource(w http.ResponseWriter, r *http.Request) error {
	var input alert.SeasonalBaselineInput
	if err := decodeJSON(r, &input); err != nil {
		return err
	}
	return s.writeAlertSeasonalSource(w, r, &input)
}

func (s *Server) handleDeleteAlertSeasonalSource(w http.ResponseWriter, r *http.Request) error {
	return s.writeAlertSeasonalSource(w, r, nil)
}

func (s *Server) writeAlertSeasonalSource(w http.ResponseWriter, r *http.Request, input *alert.SeasonalBaselineInput) error {
	actor := auth.PrincipalFrom(r.Context())
	state, err := s.setAlertSeasonalSource(r.Context(), actor, r.PathValue("id"), input, s.pathAlertRequestCredential(r, actor))
	if err != nil {
		return alertSeasonalError(err)
	}
	writeJSON(w, http.StatusOK, state)
	return nil
}

func alertSeasonalError(err error) error {
	if errors.Is(err, store.ErrAlertSeasonalChanged) || errors.Is(err, store.ErrAlertQueryChanged) {
		return apierror.Conflict("the seasonal rule or its current source changed")
	}
	if errors.Is(err, alert.ErrSeasonalSource) {
		return apierror.Validation("a supported baseline rule and current seasonal source are required")
	}
	return err
}

func (s *Server) getAlertSeasonalSource(ctx context.Context, actor *auth.Principal, id string, credential func(context.Context) error) (alertSeasonalState, error) {
	var state alertSeasonalState
	ctx, rule, err := s.beginAlertSeasonalSource(ctx, actor, id, permAlertRead, credential)
	if err != nil {
		return state, err
	}
	state = seasonalState(rule, nil)
	if !rule.HasSeasonalSource {
		return state, credential(ctx)
	}
	if err := s.authorizeSeasonalSettingsKind(ctx, actor, *rule); err != nil {
		return alertSeasonalState{}, err
	}
	stored, err := s.loadSeasonalRuleSource(ctx, *rule, flowstore.ExplorerOperationBudget(ctx, s.flowStore).MemoryBytes/8)
	if err != nil {
		return alertSeasonalState{}, err
	}
	if stored.Config.Flow != nil {
		view, err := s.currentSeasonalFlowView(ctx, actor, stored.Config.Flow.ViewID)
		if err != nil {
			return alertSeasonalState{}, err
		}
		state.StaleRevision = view.Version != stored.Config.Flow.ViewVersion
	}
	if stored.Config.TestID != "" {
		if _, err := s.seasonalTestRevision(ctx, actor, stored.Config.TestID, stored.TestRevision); err != nil {
			return alertSeasonalState{}, err
		}
	}
	if err := credential(ctx); err != nil {
		return alertSeasonalState{}, err
	}
	state.Source = &stored.Config
	return state, nil
}

func (s *Server) setAlertSeasonalSource(ctx context.Context, actor *auth.Principal, id string, input *alert.SeasonalBaselineInput, credential func(context.Context) error) (alertSeasonalState, error) {
	var none alertSeasonalState
	ctx, rule, err := s.beginAlertSeasonalSource(ctx, actor, id, permAlertWrite, credential)
	if err != nil {
		return none, err
	}
	if rule.Type != alert.Baseline || rule.HasDependencyPolicy || rule.HasTagFilter {
		return none, alert.ErrSeasonalSource
	}
	if input == nil && !rule.HasSeasonalSource {
		return seasonalState(rule, nil), nil
	}
	if input != nil && ((rule.Metric == alert.SeasonalFlowMetric) != (input.Flow != nil)) {
		return none, alert.ErrSeasonalSource
	}
	source, err := s.prepareAlertSeasonalSource(ctx, actor, input)
	if err != nil {
		return none, err
	}
	if source != nil && source.Config.TestID != "" {
		if _, err := bindSeasonalTestSelector(*rule, source.Config.TestID); err != nil {
			return none, err
		}
	}
	if err := credential(ctx); err != nil {
		return none, err
	}
	return s.updateAlertSeasonalSource(ctx, actor, rule, source)
}

func (s *Server) prepareAlertSeasonalSource(ctx context.Context, actor *auth.Principal, input *alert.SeasonalBaselineInput) (*alert.SeasonalSource, error) {
	if input == nil {
		return nil, nil
	}
	if _, err := input.Model(); err != nil {
		return nil, apierror.Validation("check the timezone, holiday dates and minimum change").Wrap(err)
	}
	if input.Flow != nil {
		return s.prepareAlertSeasonalFlowSettings(ctx, actor, input)
	}
	source := alert.SeasonalSource{Version: 1, OwnerUserID: actor.UserID, Config: *input,
		ReadGrants: alertReadGrants(actor, func(p string) bool { return p == "metrics.read" || (p == "test.read" && input.TestID != "") })}
	if input.TestID != "" {
		version, err := s.seasonalTestRevision(ctx, actor, input.TestID, nil)
		if err != nil {
			return nil, err
		}
		source.TestRevision = &version
	}
	ceiling, err := source.CredentialCeiling(actor.TenantID)
	if err != nil {
		return nil, apierror.Forbidden("the current credential requires a metric read grant")
	}
	if err := s.authorizeSeasonalMetricRead(ctx, ceiling); err != nil {
		return nil, err
	}
	return &source, nil
}

func (s *Server) beginAlertSeasonalSource(ctx context.Context, actor *auth.Principal, id, permission string, credential func(context.Context) error) (context.Context, *alert.Rule, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return nil, nil, err
	}
	if credential == nil {
		return nil, nil, apierror.Unauthorized("an originating credential is required")
	}
	if err := credential(ctx); err != nil {
		return nil, nil, err
	}
	ctx, _, err := s.alertQueryRequest(ctx, actor, permission)
	if err != nil {
		return nil, nil, err
	}
	var rule *alert.Rule
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		rule, err = (store.AlertRules{}).Get(ctx, sc, id)
		return err
	})
	return ctx, rule, err
}

func (s *Server) updateAlertSeasonalSource(ctx context.Context, actor *auth.Principal, rule *alert.Rule, source *alert.SeasonalSource) (alertSeasonalState, error) {
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return alertSeasonalState{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	var updated *alert.Rule
	err := tenancy.InTenant(tenancy.WithSiloTableLock(ctx), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		updated, err = s.persistAlertSeasonalSource(ctx, sc, actor, rule, source, budget.MemoryBytes/8)
		return err
	})
	if err != nil {
		return alertSeasonalState{}, err
	}
	if source == nil {
		return seasonalState(updated, nil), nil
	}
	return seasonalState(updated, &source.Config), nil
}

func (s *Server) persistAlertSeasonalSource(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, rule *alert.Rule, source *alert.SeasonalSource, memory int64) (*alert.Rule, error) {
	updated, err := (store.AlertRules{}).SetSeasonalSource(ctx, sc, rule.ID, rule.UpdatedAt, source, memory,
		func(ctx context.Context, sc tenancy.Scope) error {
			return s.checkAlertSeasonalEdit(ctx, sc, actor, source)
		})
	if err != nil {
		return nil, err
	}
	action := "alert.seasonal_source.set"
	if source == nil {
		action = "alert.seasonal_source.clear"
	}
	if err := audit.TenantRecord(ctx, sc, actor.UserID, action, rule.ID, map[string]any{"rule_updated_at": updated.UpdatedAt}); err != nil {
		return nil, err
	}
	return updated, nil
}

func (s *Server) checkAlertSeasonalEdit(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, source *alert.SeasonalSource) error {
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	requestContext, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	if err := s.authorize(requestContext, principal, permAlertWrite, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil || source == nil {
		return err
	}
	return s.authorizeSeasonalPublication(ctx, sc, source)
}

func seasonalState(rule *alert.Rule, input *alert.SeasonalBaselineInput) alertSeasonalState {
	return alertSeasonalState{RuleID: rule.ID, RuleUpdatedAt: rule.UpdatedAt, Configured: rule.HasSeasonalSource, Enabled: rule.Enabled, Source: input}
}

func (s *Server) authorizeSeasonalSettingsKind(ctx context.Context, actor *auth.Principal, rule alert.Rule) error {
	if rule.Metric == alert.SeasonalFlowMetric {
		_, err := s.authorizeFlowViewPrincipal(ctx, actor, false)
		return err
	}
	return s.authorizeSeasonalMetricRead(ctx, actor)
}

func (s *Server) prepareAlertSeasonalFlowSettings(ctx context.Context, actor *auth.Principal, input *alert.SeasonalBaselineInput) (*alert.SeasonalSource, error) {
	source := alert.SeasonalSource{Version: 1, OwnerUserID: actor.UserID, Config: *input,
		ReadGrants: alertReadGrants(actor, func(p string) bool { return p == permAIQuery || reportFlowReadPermission(p) })}
	ceiling, err := source.CredentialCeiling(actor.TenantID)
	if err != nil {
		return nil, apierror.Forbidden("the current credential needs the saved-flow read grants")
	}
	if err := s.authorizeSeasonalFlowSelection(ctx, ceiling, *input.Flow); err != nil {
		return nil, err
	}
	return &source, nil
}
