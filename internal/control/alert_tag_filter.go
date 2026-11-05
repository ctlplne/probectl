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
	"net/http"
	"strconv"
	"time"

	gouuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Callers hold one existing query admission. No client tenant/owner/binding is
// accepted; current user authority and definitions come from tenant RLS.
func prepareAlertTagFilter(ctx context.Context, pool *pgxpool.Pool, source flowstore.Store, actor *auth.Principal, input alert.TagFilterInput, preserved map[string]string) (*alert.TagFilter, error) {
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return nil, apierror.Unauthorized("a current user is required for alert metadata")
	}
	if input.TargetKind != "test" || input.Filter == nil {
		return nil, apierror.Validation("a current test tag filter is required")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, source)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("alert metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	authority, err := loadAlertTagAuthority(ctx, pool, actor.TenantID, actor.UserID)
	if err != nil {
		return nil, err
	}
	for _, permission := range append(alertTagPermissions(), permAlertWrite) {
		if !authority.permitsRequest(ctx, actor, permission) {
			return nil, apierror.Forbidden("current alert and source grants are required")
		}
	}
	if !authority.permits(ctx, authority.principal, map[string]string{auth.ResourceTenantKey: actor.TenantID}) {
		return nil, apierror.Forbidden("the current user cannot delegate this metadata read without a live MFA assertion")
	}
	snapshot, err := store.NewTagSnapshots(pool).LoadTests(ctx, nil, budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	normalized, ids, err := snapshot.BindFilter(ctx, actor.TenantID, input.Filter, budget.MemoryBytes/4)
	if err != nil {
		return nil, err
	}
	if preserved != nil {
		if len(ids) != len(preserved) {
			return nil, flow.ErrQueryViewStaleTag
		}
		for field, id := range ids {
			if preserved[field] != id {
				return nil, flow.ErrQueryViewStaleTag
			}
		}
	}
	revision, asOf, err := snapshot.Clock()
	if err != nil {
		return nil, err
	}
	out := &alert.TagFilter{Version: alert.TagFilterVersion, TargetKind: "test", Filter: normalized, TagIDs: ids,
		OwnerUserID: actor.UserID, TagRevision: strconv.FormatInt(revision, 10), AsOf: asOf.UTC().Format(time.RFC3339Nano)}
	// Use the same per-rule decode reservation as GetTagFilter before accepting
	// configuration, including bindings/clock overhead outside the grammar.
	encoded, err := json.Marshal(out)
	if err != nil || int64(len(encoded)) > budget.MemoryBytes/32 {
		return nil, store.ErrTagSnapshotBudget
	}
	return out, nil
}

func readAlertTagFilter(ctx context.Context, pool *pgxpool.Pool, source flowstore.Store, actor *auth.Principal, id string) (alert.TagFilterState, error) {
	if actor == nil || actor.TenantID == "" || actor.UserID == "" {
		return alert.TagFilterState{}, apierror.Unauthorized("a current user is required for alert metadata")
	}
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.TagFilterState{}, err
	}
	budget := flowstore.ExplorerOperationBudget(ctx, source)
	if err := budget.Validate(); err != nil {
		return alert.TagFilterState{}, apierror.Unavailable("alert metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx = tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID))
	authority, err := loadAlertTagAuthority(ctx, pool, actor.TenantID, actor.UserID)
	if err != nil {
		return alert.TagFilterState{}, err
	}
	for _, permission := range append(alertTagPermissions(), permAlertRead) {
		if !authority.permitsRequest(ctx, actor, permission) {
			return alert.TagFilterState{}, apierror.Forbidden("current alert and source read grants are required")
		}
	}
	var out alert.TagFilterState
	err = tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		out.RuleID, out.HasTagFilter = rule.ID, rule.HasTagFilter
		if rule.HasTagFilter {
			out.TagFilter, err = (store.AlertRules{}).GetTagFilter(ctx, sc, rule.ID, rule.UpdatedAt, budget.MemoryBytes/4)
			if err != nil {
				return err
			}
			if out.TagFilter == nil {
				return store.ErrAlertTagFilterChanged
			}
		}
		out.Editor, err = readAlertTagEditor(ctx, sc, budget.MemoryBytes/4)
		return err
	})
	if err != nil {
		return alert.TagFilterState{}, err
	}
	if err := checkAlertTagResponse(ctx, source, out); err != nil {
		return alert.TagFilterState{}, err
	}
	return out, nil
}

func readAlertTagEditor(ctx context.Context, sc tenancy.Scope, maxBytes int64) (*alert.TagFilterEditorSchema, error) {
	if maxBytes < 2048 {
		return nil, store.ErrTagSnapshotBudget
	}
	definitions, err := (store.TagDefinitions{}).ListBounded(ctx, sc, maxBytes)
	if err != nil {
		return nil, err
	}
	// Account for the shared vocabulary's derived fields/maps as well as the
	// curated output, before expanding any current definitions.
	used := int64(2048)
	for _, definition := range definitions {
		amount := int64(4096 + len(definition.Key)*16 + len(definition.ID)*8)
		if amount > maxBytes-used {
			return nil, store.ErrTagSnapshotBudget
		}
		used += amount
	}
	vocabulary, err := flow.NewTagQueryVocabulary(sc.Tenant.String(), definitions)
	if err != nil {
		return nil, err
	}
	var revision int64
	var asOf time.Time
	if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1),1),transaction_timestamp()`, sc.Tenant.String()).Scan(&revision, &asOf); err != nil {
		return nil, err
	}
	out := &alert.TagFilterEditorSchema{TagRevision: strconv.FormatInt(revision, 10), AsOf: asOf.UTC().Format(time.RFC3339Nano), Fields: []alert.TagFilterField{},
		Limits: alert.TagFilterLimits{MaxGroupEntries: flow.MaxQueryGroupEntries, MaxExpandedConditions: flow.MaxQueryPredicates, MaxFilterDepth: flow.MaxQueryFilterDepth,
			MaxRegexBytes: flow.MaxQueryRegexBytes, MaxValuesPerPredicate: flow.MaxQueryValues, MaxValueBytes: flow.MaxQueryValueBytes, GrammarBytes: flow.MaxPlanGrammarBytes}}
	for _, definition := range definitions {
		field, ok := vocabulary.Lookup("tag." + definition.Key)
		if !ok || field.TagID != definition.ID || field.Type != flow.QueryText {
			return nil, store.ErrTagSnapshotUnavailable
		}
		out.Fields = append(out.Fields, alert.TagFilterField{Name: field.Name, TagID: field.TagID, Type: field.Type, Operators: append([]flow.QueryOperator(nil), field.Operators...)})
	}
	return out, ctx.Err()
}

func checkAlertTagResponse(ctx context.Context, source flowstore.Store, value alert.TagFilterState) error {
	budget := flowstore.ExplorerOperationBudget(ctx, source)
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > budget.ResponseBytes || int64(len(encoded)) > budget.MemoryBytes/4 {
		return store.ErrTagSnapshotBudget
	}
	return ctx.Err()
}

func alertTagFilterError(w http.ResponseWriter, err error) error {
	if errors.Is(err, store.ErrAlertTagFilterChanged) || errors.Is(err, flow.ErrQueryViewStaleTag) {
		return apierror.Conflict("alert metadata configuration or referenced tags changed; refresh before saving")
	}
	if errors.Is(err, store.ErrTagSnapshotBudget) || errors.Is(err, tags.ErrInvalid) || errors.Is(err, tags.ErrScopeMismatch) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return tagSubjectAPIError(err)
	}
	return tagQueryResponseError(w, err)
}

func validateAlertTagRuleID(id string) error {
	parsed, err := gouuid.Parse(id)
	if err != nil || parsed == gouuid.Nil || parsed.String() != id {
		return apierror.Validation("a canonical alert rule ID is required")
	}
	return nil
}

func (s *Server) beginAlertTagOperation(w http.ResponseWriter, r *http.Request) (*http.Request, func(), error) {
	release, err := s.beginQuery(w, r)
	if err != nil {
		return r, nil, err
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if err := budget.Validate(); err != nil {
		release()
		return r, nil, apierror.Unavailable("alert metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget.ExecutionLimit)
	return r.WithContext(ctx), func() { cancel(); release() }, nil
}

func (s *Server) handleGetAlertTagFilter(w http.ResponseWriter, r *http.Request) error {
	r, release, err := s.beginAlertTagOperation(w, r)
	if err != nil {
		return err
	}
	defer release()
	out, err := readAlertTagFilter(r.Context(), s.pool, s.flowStore, auth.PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return alertTagFilterError(w, err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) handlePutAlertTagFilter(w http.ResponseWriter, r *http.Request) error {
	r, release, err := s.beginAlertTagOperation(w, r)
	if err != nil {
		return err
	}
	defer release()
	var input alert.TagFilterInput
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &input); err != nil {
		return err
	}
	out, err := s.setAlertTagFilter(r, r.PathValue("id"), input)
	if err != nil {
		return alertTagFilterError(w, err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// Both REST and named native MCP hold one query admission before entering this
// shared preparation/transaction/audit path. The complete operation is bounded.
func (s *Server) setAlertTagFilter(r *http.Request, id string, input alert.TagFilterInput) (alert.TagFilterState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.TagFilterState{}, err
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.TagFilterState{}, apierror.Unavailable("alert metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget.ExecutionLimit)
	defer cancel()
	r = r.WithContext(ctx)
	actor := auth.PrincipalFrom(ctx)
	prepared, err := prepareAlertTagFilter(ctx, s.pool, s.flowStore, actor, input, nil)
	if err != nil {
		return alert.TagFilterState{}, err
	}
	out := alert.TagFilterState{RuleID: id, HasTagFilter: true, TagFilter: prepared}
	if err := checkAlertTagResponse(ctx, s.flowStore, out); err != nil {
		return alert.TagFilterState{}, err
	}
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if rule.Type == alert.Trap {
			return apierror.Validation("current test tag filters require a metric rule")
		}
		if _, err := (store.AlertRules{}).SetTagFilter(ctx, sc, rule.ID, rule.UpdatedAt, prepared); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "alert.tag_filter.set", rule.ID, map[string]any{"target_kind": "test", "owner_user_id": actor.UserID, "tag_revision": prepared.TagRevision})
	})
	if err != nil {
		return alert.TagFilterState{}, err
	}
	return out, nil
}

func (s *Server) handleDeleteAlertTagFilter(w http.ResponseWriter, r *http.Request) error {
	r, release, err := s.beginAlertTagOperation(w, r)
	if err != nil {
		return err
	}
	defer release()
	if _, err := s.clearAlertTagFilter(r, r.PathValue("id")); err != nil {
		return alertTagFilterError(w, err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *Server) clearAlertTagFilter(r *http.Request, id string) (alert.TagFilterState, error) {
	if err := validateAlertTagRuleID(id); err != nil {
		return alert.TagFilterState{}, err
	}
	actor := auth.PrincipalFrom(r.Context())
	if actor == nil || actor.UserID == "" {
		return alert.TagFilterState{}, apierror.Unauthorized("a current user is required for alert metadata")
	}
	budget := flowstore.ExplorerOperationBudget(r.Context(), s.flowStore)
	if err := budget.Validate(); err != nil {
		return alert.TagFilterState{}, apierror.Unavailable("alert metadata cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(r.Context(), tenancy.ID(actor.TenantID)), budget.ExecutionLimit)
	defer cancel()
	r = r.WithContext(ctx)
	authority, err := loadAlertTagAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return alert.TagFilterState{}, err
	}
	if !authority.permitsRequest(ctx, actor, permAlertWrite) {
		return alert.TagFilterState{}, apierror.Forbidden("current alert write permission is required")
	}
	out := alert.TagFilterState{RuleID: id}
	if err := checkAlertTagResponse(ctx, s.flowStore, out); err != nil {
		return alert.TagFilterState{}, err
	}
	err = s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		rule, err := (store.AlertRules{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if _, err := (store.AlertRules{}).SetTagFilter(ctx, sc, rule.ID, rule.UpdatedAt, nil); err != nil {
			return err
		}
		return s.recordAudit(ctx, sc, r, "alert.tag_filter.clear", rule.ID, nil)
	})
	if err != nil {
		return alert.TagFilterState{}, err
	}
	return out, nil
}
