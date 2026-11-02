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
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowTagQueryKey struct{}

// flowQueryUsesTags inspects only field names. It grants no authority: the
// tenant snapshot, permissions and store boundary validate the selected key.
func flowQueryUsesTags(query ai.ExplorerQuery) bool {
	check := func(name string) bool {
		return strings.HasPrefix(strings.ToLower(strings.TrimSpace(name)), "tag.")
	}
	for _, name := range append(append([]string{}, query.Dimensions...), query.Groupings...) {
		if check(name) {
			return true
		}
	}
	for name := range query.Filters {
		if check(name) {
			return true
		}
	}
	if query.Flow == nil {
		return false
	}
	for _, name := range append(append(append([]string{}, query.Flow.GroupBy...), query.Flow.MatrixWith...),
		flow.QueryFilterFields(query.Flow.Filter)...) {
		if check(name) {
			return true
		}
	}
	return false
}

// loadFlowTagQuery pins one tenant's definitions, ownership and tag rules at
// one revision. The three materializations each receive a quarter of the
// existing Explorer memory allowance; no partial projection is usable.
func (s *Server) loadFlowTagQuery(ctx context.Context, principal *auth.Principal) (*flowstore.TagQueryData, error) {
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, principal, permTagsRead, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
		return nil, err
	}
	if s.pool == nil {
		return nil, apierror.Unavailable("tenant tag query storage is unavailable")
	}
	budget := flowstore.ExplorerQueryBudget(s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("flow cost policy unavailable")
	}
	limit := budget.MemoryBytes / 4
	ctx = tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID))
	snapshot, err := store.NewTagSnapshots(s.pool).LoadTenant(ctx, limit)
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	revision, err := snapshot.Revision()
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	definitions, err := snapshot.Definitions()
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	projection, err := snapshot.ProjectExporters(limit)
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	data, err := flowstore.NewTagQueryData(principal.TenantID, revision, definitions, projection, limit)
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	return data, nil
}

func flowTagQueryError(err error) error {
	if errors.Is(err, store.ErrTagSnapshotBudget) || errors.Is(err, flowstore.ErrExplorerBudget) {
		return flowExplorerStoreError(flowstore.ErrExplorerBudget)
	}
	return apierror.Unavailable("tenant tag query snapshot is unavailable")
}

func flowTagQueryFromContext(ctx context.Context, tenant string) (*flowstore.TagQueryData, error) {
	value, _ := ctx.Value(flowTagQueryKey{}).(*flowstore.TagQueryData)
	if value == nil {
		return nil, nil
	}
	if _, err := value.Revision(tenant); err != nil {
		return nil, apierror.Unavailable("tenant tag query scope is unavailable")
	}
	return value, nil
}

func flowTagQueryContext(ctx context.Context, data *flowstore.TagQueryData) context.Context {
	return context.WithValue(ctx, flowTagQueryKey{}, data)
}

func (s *Server) normalizeExplorerQuery(ctx context.Context, principal *auth.Principal,
	raw ai.ExplorerQuery, now time.Time) (ai.ExplorerQuery, context.Context, error) {
	if principal == nil || strings.TrimSpace(principal.TenantID) == "" {
		return ai.ExplorerQuery{}, ctx, apierror.Unauthorized("tenant identity required for Explorer queries")
	}
	if raw.Source != ai.ExplorerFlow {
		query, err := ai.NormalizeExplorerQuery(raw, now)
		if err != nil {
			return ai.ExplorerQuery{}, ctx, apierror.Validation(err.Error())
		}
		return query, ctx, nil
	}
	data, err := flowTagQueryFromContext(ctx, principal.TenantID)
	if err != nil {
		return ai.ExplorerQuery{}, ctx, err
	}
	if data == nil && flowQueryUsesTags(raw) {
		data, err = s.loadFlowTagQuery(ctx, principal)
		if err != nil {
			return ai.ExplorerQuery{}, ctx, err
		}
		ctx = flowTagQueryContext(ctx, data)
	}
	var query ai.ExplorerQuery
	if data == nil {
		query, err = ai.NormalizeExplorerQuery(raw, now)
	} else {
		vocabulary, vocabErr := data.Vocabulary(principal.TenantID)
		if vocabErr != nil {
			return ai.ExplorerQuery{}, ctx, apierror.Unavailable("tenant tag query scope is unavailable")
		}
		query, err = ai.NormalizeExplorerQueryWithVocabulary(raw, now, vocabulary)
	}
	if err != nil {
		return ai.ExplorerQuery{}, ctx, apierror.Validation(err.Error())
	}
	return query, ctx, nil
}

// flowQueryFields exposes the tenant's tag keys only when tags.read is granted.
// The schema's native fields stay available to flow readers without that grant.
func (s *Server) flowQueryFields(ctx context.Context, principal *auth.Principal) ([]flow.QueryField, error) {
	fields := flow.QueryFields()
	if principal == nil || principal.TenantID == "" || s.pool == nil {
		return fields, nil
	}
	decision, err := s.decide(ctx, principal, permTagsRead, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: principal.TenantID})
	if err != nil {
		return nil, err
	}
	if decision != auth.DecisionAllowed {
		return fields, nil
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID))
	var definitions []tags.Definition
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, scope tenancy.Scope) error {
		var loadErr error
		definitions, loadErr = (store.TagDefinitions{}).List(ctx, scope)
		return loadErr
	})
	if err != nil {
		return nil, apierror.Unavailable("tenant tag query schema is unavailable")
	}
	vocabulary, err := flow.NewTagQueryVocabulary(principal.TenantID, definitions)
	if err != nil {
		return nil, apierror.Unavailable("tenant tag query schema is unavailable")
	}
	return vocabulary.Fields()
}
