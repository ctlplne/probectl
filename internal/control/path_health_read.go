// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type pathHealthResult struct {
	TestID    string          `json:"test_id"`
	ContextID string          `json:"context_id,omitempty"`
	Status    string          `json:"status"`
	Coverage  string          `json:"coverage"`
	Items     []pathEntityHop `json:"items"`
	Truncated bool            `json:"truncated"`
}

type pathHealthSnapshot struct {
	result  pathHealthResult
	binding *store.PathTestBinding
}

func (s *Server) handleGetPathHealth(w http.ResponseWriter, r *http.Request) error {
	query, err := s.beginPathHealth(r)
	if err != nil {
		return pathHealthError(err)
	}
	defer query.op.done()
	snapshot, err := s.readPathHealth(query)
	if err != nil {
		return pathHealthError(err)
	}
	body, err := json.Marshal(snapshot.result)
	if err != nil {
		return apierror.Unavailable("complete path health output is unavailable")
	}
	if int64(len(body)) > query.op.budget.ResponseBytes {
		return apierror.TooLarge("complete path health output exceeds response admission")
	}
	if err := s.revalidatePathHealthSnapshot(query, snapshot); err != nil {
		return pathHealthError(err)
	}
	if err := s.revalidatePathHealthCredential(query); err != nil {
		return pathHealthError(err)
	}
	writeJSON(w, http.StatusOK, json.RawMessage(body))
	return nil
}

// Both REST and native MCP use this complete current read. The caller owns
// finite operation admission and refreshes its exact transport credential at
// publication. No caller-controlled tenant, device, ifIndex or capture enters.
func (s *Server) readPathHealth(query *pathHealthOperation) (pathHealthSnapshot, error) {
	none := pathHealthSnapshot{}
	ctx, actor := query.op.request.Context(), query.op.actor
	id := query.op.request.PathValue("id")
	if err := s.authorizePathHealthTenant(query); err != nil {
		return none, err
	}
	if _, err := s.testTarget(query.op.request); err != nil {
		return none, err
	}
	registry := store.NewEntityRegistry(s.pool)
	binding, err := registry.PathTestBinding(ctx, actor.TenantID, id)
	result := pathHealthResult{TestID: id, Status: "unbound", Coverage: "no_bound_context", Items: []pathEntityHop{}}
	if errors.Is(err, pgx.ErrNoRows) {
		return pathHealthSnapshot{result: result}, nil
	}
	if err != nil {
		return none, entityAPIError(err)
	}
	if err := s.authorizePathHealth(query, binding.Scope, nil); err != nil {
		return none, err
	}
	result.ContextID = binding.Scope.ContextID
	result.Status, result.Coverage = "awaiting_trace", "no_post_binding_trace"
	snapshot := pathHealthSnapshot{result: result, binding: &binding}
	p, found, err := latestPathAfterBinding(ctx, s.pathStore, actor.TenantID, binding)
	if err != nil {
		return none, err
	}
	if !found {
		return snapshot, nil
	}
	items, addresses, err := admittedPathHealthHops(p, query.op.budget.MemoryBytes)
	if err != nil {
		return none, err
	}
	resolved, err := registry.ResolveAddressesWithBudget(ctx, binding.Scope, addresses, query.op.budget.MemoryBytes)
	if err != nil {
		return none, err
	}
	for i := range items {
		items[i].Resolution = entity.Resolution{Scope: binding.Scope, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: items[i].IP}, Status: entity.Unresolved}
		if alias, err := items[i].Resolution.Alias.Normalize(); err == nil {
			items[i].Resolution = resolved[alias.Value]
		}
	}
	if err := s.populatePathHealth(query, binding, items); err != nil {
		return none, err
	}
	snapshot.result.Items = items
	snapshot.result.Status, snapshot.result.Coverage = "current", "registered_sources_only"
	return snapshot, nil
}

func admittedPathHealthHops(p *path.Path, memoryBytes int64) ([]pathEntityHop, []string, error) {
	items, addresses := []pathEntityHop{}, []string{}
	seen := map[string]bool{}
	for _, hop := range p.Hops {
		for _, node := range hop.Nodes {
			if node.IP == "" {
				continue
			}
			if int64(len(items)) >= memoryBytes/8192 {
				return nil, nil, apierror.TooLarge("complete path health exceeds resource admission")
			}
			items = append(items, pathEntityHop{TTL: hop.TTL, IP: node.IP})
			if alias, err := (entity.AliasKey{Kind: entity.AddressAlias, Value: node.IP}).Normalize(); err == nil && !seen[alias.Value] {
				seen[alias.Value] = true
				addresses = append(addresses, alias.Value)
			}
		}
	}
	return items, addresses, nil
}

func (s *Server) authorizePathHealthTenant(query *pathHealthOperation) error {
	ctx, actor := query.op.request.Context(), query.op.actor
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil || status != "active" {
		return apierror.Forbidden("current path health tenant is inactive or unavailable")
	}
	current, err := loadCurrentUserAuthority(ctx, s.pool, actor.TenantID, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	for _, permission := range []string{permTestRead, ai.PermEntitiesRead, ai.PermMetricsRead} {
		if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) revalidatePathHealthSnapshot(query *pathHealthOperation, snapshot pathHealthSnapshot) error {
	if err := s.authorizePathHealthTenant(query); err != nil {
		return err
	}
	if _, err := s.testTarget(query.op.request); err != nil {
		return err
	}
	if snapshot.binding != nil {
		return s.revalidatePathHealth(query, *snapshot.binding, snapshot.result.Items)
	}
	ctx, actor := query.op.request.Context(), query.op.actor
	_, err := store.NewEntityRegistry(s.pool).PathTestBinding(tenancy.WithTenant(ctx, tenancy.ID(actor.TenantID)), actor.TenantID, snapshot.result.TestID)
	if !errors.Is(err, pgx.ErrNoRows) {
		return apierror.Unavailable("path context changed; retry")
	}
	return ctx.Err()
}
