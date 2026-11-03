// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type testTagAuthorize func(context.Context, *auth.Principal, string, map[string]string) (bool, error)

func (s *Server) handleResolveTestTagContext(w http.ResponseWriter, r *http.Request) error {
	release, err := s.beginQuery(w, r)
	if err != nil {
		return err
	}
	defer release()
	var input tags.TestContextInput
	if err := decodeJSONLimit(r, flow.MaxPlanGrammarBytes, &input); err != nil {
		return err
	}
	out, err := resolveTestTagContext(r.Context(), auth.PrincipalFrom(r.Context()), s.pool, s.flowStore, input, s.authorizeTestTagResource)
	if err != nil {
		return tagQueryResponseError(w, err)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) authorizeTestTagResource(ctx context.Context, principal *auth.Principal, permission string, resource map[string]string) (bool, error) {
	decision, err := s.decide(ctx, principal, permission, auth.RBACGlobal, resource)
	return decision == auth.DecisionAllowed, err
}

// Every caller holds one existing query admission before entering this common
// read. Resource attributes come from the same RLS snapshot as the annotations.
func resolveTestTagContext(ctx context.Context, principal *auth.Principal, pool *pgxpool.Pool, flowStore flowstore.Store, input tags.TestContextInput, authorize testTagAuthorize) (tags.TestContextResolution, error) {
	if principal == nil || principal.TenantID == "" {
		return tags.TestContextResolution{}, apierror.Unauthorized("tenant identity required for test tags")
	}
	if authorize == nil {
		return tags.TestContextResolution{}, apierror.Unavailable("test tag policy is unavailable")
	}
	permission, err := tagSubjectReadPermission("test")
	if err != nil {
		return tags.TestContextResolution{}, err
	}
	permissions := []string{permTagsRead, permission}
	for _, current := range permissions {
		allowed, err := authorize(ctx, principal, current, map[string]string{auth.ResourceTenantKey: principal.TenantID})
		if err != nil {
			return tags.TestContextResolution{}, err
		}
		if !allowed {
			return tags.TestContextResolution{}, apierror.Forbidden("current tag and test read permissions are required")
		}
	}
	if input.TestIDs == nil {
		return tags.TestContextResolution{}, apierror.Validation("test_ids must be an array")
	}
	for _, id := range input.TestIDs {
		if len(id) > 128 {
			return tags.TestContextResolution{}, apierror.Validation("test reference exceeds its input bound")
		}
	}
	budget := flowstore.ExplorerOperationBudget(ctx, flowStore)
	if err := budget.Validate(); err != nil {
		return tags.TestContextResolution{}, apierror.Unavailable("test tag cost policy is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, budget.ExecutionLimit)
	defer cancel()
	ctx = tenancy.WithTenant(ctx, tenancy.ID(principal.TenantID))
	limit := budget.MemoryBytes / 4
	snapshot, err := store.NewTagSnapshots(pool).LoadTests(ctx, input.TestIDs, limit)
	if err != nil {
		return tags.TestContextResolution{}, tagSubjectAPIError(err)
	}
	revision, asOf, err := snapshot.Clock()
	if err != nil {
		return tags.TestContextResolution{}, tagSubjectAPIError(err)
	}
	records, err := snapshot.Contexts()
	if err != nil {
		return tags.TestContextResolution{}, tagSubjectAPIError(err)
	}
	if int64(len(records)) > limit/1024 {
		return tags.TestContextResolution{}, tagSubjectAPIError(store.ErrTagSnapshotBudget)
	}
	allowed := map[string]bool{}
	for _, record := range records {
		if record.TenantID != principal.TenantID {
			return tags.TestContextResolution{}, apierror.Unavailable("test tag context scope is unavailable")
		}
		disclose := true
		for _, current := range permissions {
			decision, err := authorize(ctx, principal, current, entityContextResource(record))
			if err != nil {
				return tags.TestContextResolution{}, err
			}
			disclose = disclose && decision
		}
		allowed[record.ContextID] = disclose
	}
	out := tags.TestContextResolution{TagRevision: strconv.FormatInt(revision, 10), AsOf: asOf.UTC().Format(time.RFC3339Nano), Items: []tags.SubjectResolution{}}
	seen := map[string]bool{}
	used := int64(512)
	for _, id := range input.TestIDs {
		resolved, err := snapshot.ResolveContext(ctx, principal.TenantID, id, allowed, limit)
		if err != nil {
			return tags.TestContextResolution{}, tagSubjectAPIError(err)
		}
		if resolved == nil || seen[resolved.ID] {
			continue
		}
		item := projectSubjectTags(*resolved)
		encoded, err := json.Marshal(item)
		amount := int64(len(encoded)) + 2048
		if err != nil || amount > limit-used {
			return tags.TestContextResolution{}, tagSubjectAPIError(store.ErrTagSnapshotBudget)
		}
		used += amount
		seen[resolved.ID] = true
		out.Items = append(out.Items, item)
	}
	encoded, err := json.Marshal(out)
	if err != nil || int64(len(encoded)) > budget.ResponseBytes || int64(len(encoded)) > budget.MemoryBytes/2 {
		return tags.TestContextResolution{}, tagSubjectAPIError(store.ErrTagSnapshotBudget)
	}
	if err := ctx.Err(); err != nil {
		return tags.TestContextResolution{}, tagSubjectAPIError(err)
	}
	return out, nil
}
