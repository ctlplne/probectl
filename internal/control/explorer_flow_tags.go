// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"slices"
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

// flowQueryTagHints inspects only bounded field and reference names. It grants
// no authority: the tenant snapshot, permissions and store boundary validate
// the selected key. An oversized filter is rejected by normal normalization.
func flowQueryTagHints(query ai.ExplorerQuery) (direct, saved bool, subjects []string) {
	check := func(name string) bool {
		name = strings.ToLower(strings.TrimSpace(name))
		for _, subject := range relatedFlowTagSubjects([]string{name}) {
			if !slices.Contains(subjects, subject) {
				subjects = append(subjects, subject)
			}
		}
		return strings.HasPrefix(name, "tag.")
	}
	for _, name := range append(append([]string{}, query.Dimensions...), query.Groupings...) {
		if check(name) {
			direct = true
		}
	}
	for name := range query.Filters {
		if check(name) {
			direct = true
		}
	}
	if query.Flow == nil {
		return direct, false, subjects
	}
	for _, name := range append(append([]string{}, query.Flow.GroupBy...), query.Flow.MatrixWith...) {
		if check(name) {
			direct = true
		}
	}
	type node struct {
		group *flow.QueryFilterGroup
		depth int
	}
	stack := []node{{group: query.Flow.Filter, depth: 1}}
	for visited := 0; len(stack) > 0 && visited < flow.MaxQueryPredicates; visited++ {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if current.group == nil || current.depth > flow.MaxQueryFilterDepth {
			continue
		}
		for _, condition := range current.group.Conditions {
			if check(condition.Field) {
				direct = true
			}
		}
		if len(current.group.Saved) > 0 {
			saved = true
		}
		for i := range current.group.Groups {
			stack = append(stack, node{group: &current.group.Groups[i], depth: current.depth + 1})
		}
	}
	return direct, saved, subjects
}

// loadFlowTagQuery pins one tenant's definitions, ownership and tag rules at
// one revision. The three materializations each receive a quarter of the
// existing Explorer memory allowance; no partial projection is usable.
func (s *Server) loadFlowTagQuery(ctx context.Context, principal *auth.Principal, subjects ...string) (*flowstore.TagQueryData, error) {
	return s.loadFlowTagQuerySnapshot(ctx, principal, subjects, true)
}

// Frozen results need current selected disclosure policy, not mutable source
// facts. Revalidation cannot silently broaden a plan's subject read grants.
func (s *Server) loadFlowTagQueryPolicy(ctx context.Context, principal *auth.Principal, subjects []string) (*flowstore.TagQueryData, error) {
	return s.loadFlowTagQuerySnapshot(ctx, principal, subjects, false)
}

func (s *Server) loadFlowTagQuerySnapshot(ctx context.Context, principal *auth.Principal, subjects []string, facts bool) (*flowstore.TagQueryData, error) {
	if principal == nil || principal.TenantID == "" {
		return nil, apierror.Unauthorized("tenant identity required for tag queries")
	}
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, principal, permTagsRead, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
		return nil, err
	}
	for _, subject := range subjects {
		permission, err := tagSubjectReadPermission(subject)
		if err != nil {
			return nil, err
		}
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
			return nil, err
		}
	}
	if s.pool == nil {
		return nil, apierror.Unavailable("tenant tag query storage is unavailable")
	}
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, apierror.Unavailable("flow cost policy unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	// REST query middleware and native MCP already hold query admission.
	// Revalidation stays inside that slot rather than charging it twice.
	limit := budget.MemoryBytes / 4
	ctx = tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID))
	var currentFacts []string
	if facts {
		currentFacts = subjects
	}
	snapshot, err := store.NewTagSnapshots(s.pool).LoadTenant(ctx, limit, currentFacts...)
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
	allowed, related, digest, err := s.flowTagContextAuthorization(ctx, principal, snapshot, limit, subjects...)
	if err != nil {
		return nil, err
	}
	projection, err := snapshot.ProjectAuthorizedExportersContext(ctx, allowed, limit, related)
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	prefixes, err := snapshot.ProjectAuthorizedPrefixesContext(ctx, allowed, related["prefix"], limit)
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	data, err := flowstore.NewTagQueryData(principal.TenantID, revision, definitions, projection, limit, flowstore.TagQuerySources{Context: ctx, Prefixes: prefixes})
	if err != nil {
		return nil, flowTagQueryError(err)
	}
	return data.WithContextAuthorization(principal.TenantID, digest)
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

func (s *Server) savedFlowQueryUsesTags(ctx context.Context, principal *auth.Principal,
	filter *flow.QueryFilterGroup) (bool, []string, error) {
	if s.pool == nil || filter == nil {
		return false, nil, nil
	}
	if err := s.authorizeNativeFlow(ctx, principal); err != nil {
		return false, nil, err
	}
	decision, err := s.decide(ctx, principal, permTagsRead, auth.RBACGlobal,
		map[string]string{auth.ResourceTenantKey: principal.TenantID})
	if err != nil || decision != auth.DecisionAllowed {
		return false, nil, err
	}
	vocabulary, err := s.loadFlowQueryVocabulary(ctx, principal)
	if err != nil {
		return false, nil, err
	}
	ctx, err = flow.WithQueryVocabulary(ctx, principal.TenantID, vocabulary)
	if err != nil {
		return false, nil, apierror.Unavailable("tenant tag query scope is unavailable")
	}
	resolved, err := flow.ResolveQueryFiltersWithVocabulary(ctx, principal.TenantID, filter,
		s.flowQueryFilters, "", vocabulary)
	if err != nil {
		if errors.Is(err, flow.ErrQueryFilterNotFound) {
			return false, nil, apierror.NotFound("saved flow filter not found")
		}
		return false, nil, apierror.Validation("saved flow filters could not be resolved within the query bounds")
	}
	names := flow.QueryFilterFields(resolved.Expression)
	uses := false
	for _, name := range names {
		uses = uses || strings.HasPrefix(name, "tag.")
	}
	return uses, relatedFlowTagSubjects(names), nil
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
	direct, saved, subjects := flowQueryTagHints(raw)
	if data == nil && saved {
		usesTag, savedSubjects, detectErr := s.savedFlowQueryUsesTags(ctx, principal, raw.Flow.Filter)
		if detectErr != nil {
			return ai.ExplorerQuery{}, ctx, detectErr
		}
		direct = direct || usesTag
		for _, subject := range savedSubjects {
			if !slices.Contains(subjects, subject) {
				subjects = append(subjects, subject)
			}
		}
	}
	if data == nil && direct {
		data, err = s.loadFlowTagQuery(ctx, principal, subjects...)
		if err != nil {
			return ai.ExplorerQuery{}, ctx, err
		}
		ctx = flowTagQueryContext(ctx, data)
	}
	if data != nil {
		vocabulary, vocabErr := data.Vocabulary(principal.TenantID)
		if vocabErr != nil {
			return ai.ExplorerQuery{}, ctx, apierror.Unavailable("tenant tag query scope is unavailable")
		}
		ctx, err = flow.WithQueryVocabulary(ctx, principal.TenantID, vocabulary)
		if err != nil {
			return ai.ExplorerQuery{}, ctx, apierror.Unavailable("tenant tag query scope is unavailable")
		}
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
	vocabulary, err := s.loadFlowQueryVocabulary(ctx, principal)
	if err != nil {
		return nil, err
	}
	return vocabulary.Fields()
}

func (s *Server) loadFlowQueryVocabulary(ctx context.Context, principal *auth.Principal) (flow.QueryVocabulary, error) {
	if principal == nil || principal.TenantID == "" || s.pool == nil {
		return flow.QueryVocabulary{}, apierror.Unavailable("tenant tag query schema is unavailable")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID))
	var definitions []tags.Definition
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, scope tenancy.Scope) error {
		var loadErr error
		definitions, loadErr = (store.TagDefinitions{}).List(ctx, scope)
		return loadErr
	})
	if err != nil {
		return flow.QueryVocabulary{}, apierror.Unavailable("tenant tag query schema is unavailable")
	}
	vocabulary, err := flow.NewTagQueryVocabulary(principal.TenantID, definitions)
	if err != nil {
		return flow.QueryVocabulary{}, apierror.Unavailable("tenant tag query schema is unavailable")
	}
	return vocabulary, nil
}

// Names are hints only; the tenant vocabulary still validates every field.
func relatedFlowTagSubjects(names []string) []string {
	result := []string{}
	for _, subject := range []string{"device", "agent", "interface", "prefix"} {
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if strings.HasPrefix(name, "tag."+subject+".") || subject == "interface" && (strings.HasPrefix(name, "tag.in_interface.") || strings.HasPrefix(name, "tag.out_interface.")) || subject == "prefix" && (strings.HasPrefix(name, "tag.src_prefix.") || strings.HasPrefix(name, "tag.dst_prefix.")) {
				result = append(result, subject)
				break
			}
		}
	}
	return result
}
