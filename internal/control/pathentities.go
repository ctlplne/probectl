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

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type pathEntityHop struct {
	Health     *pathInterfaceHealth `json:"health,omitempty"`
	TTL        int                  `json:"ttl"`
	IP         string               `json:"ip"`
	Resolution entity.Resolution    `json:"resolution"`
}

// latestPathAfterBinding requires a discovery round strictly newer than the
// operator's context assignment. ClickHouse stores millisecond timestamps, so
// a same-millisecond round is conservatively left unresolved.
func latestPathAfterBinding(ctx context.Context, paths pathstore.Store,
	tenantID string, binding store.PathTestBinding) (*path.Path, bool, error) {
	if binding.Target == "" || binding.AssignedAt.IsZero() {
		return nil, false, entity.ErrInvalidClaim
	}
	rounds, err := paths.History(ctx, tenantID, binding.Target, pathstore.HistoryQuery{
		From: binding.AssignedAt, Limit: 1,
	})
	if err != nil || len(rounds) == 0 {
		return nil, false, err
	}
	if !rounds[0].TrustedDiscoveryTime || !rounds[0].ObservedAt.After(binding.AssignedAt) {
		return nil, false, nil
	}
	return &rounds[0].Path, true, nil
}

// handleGetPathEntities joins a stored control-plane trace to *current*
// identity evidence. The test's operator-assigned context is the sole context
// selector. This read never turns a responder IP into an authoritative device.
// It is separate from the raw path API so identity permissions stay explicit.
func (s *Server) handleGetPathEntities(w http.ResponseWriter, r *http.Request) error {
	includeHealth, err := pathHealthRequested(r)
	if err != nil {
		return err
	}
	if includeHealth {
		return s.handleGetPathHealth(w, r)
	}
	_, err = s.testTarget(r)
	if err != nil {
		return err
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	principal := auth.PrincipalFrom(r.Context())
	if err := s.authorize(r.Context(), principal, ai.PermEntitiesRead, auth.RBACGlobal, nil); err != nil {
		return err
	}
	ctx := tenancy.WithTenant(r.Context(), tenancy.ID(tid))
	registry := store.NewEntityRegistry(s.pool)
	binding, err := registry.PathTestBinding(ctx, tid, r.PathValue("id"))
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, map[string]any{
			"test_id": r.PathValue("id"), "status": "unbound", "coverage": "no_bound_context", "items": []pathEntityHop{},
		})
		return nil
	}
	if err != nil {
		return entityAPIError(err)
	}
	scope := binding.Scope
	resource, err := s.entityResource(ctx, scope)
	if err != nil {
		return err
	}
	if err := s.authorize(r.Context(), principal, ai.PermEntitiesRead,
		auth.RBACGlobal, resource); err != nil {
		return err
	}
	// Use the destination read with this exact operator binding. The earlier
	// test existence check can race with a retarget and new context assignment.
	p, found, err := latestPathAfterBinding(r.Context(), s.pathStore, tid, binding)
	if err != nil {
		return apierror.Internal("path lookup failed").Wrap(err)
	}
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{
			"test_id": r.PathValue("id"), "context_id": scope.ContextID,
			"status": "awaiting_trace", "coverage": "no_post_binding_trace", "items": []pathEntityHop{},
		})
		return nil
	}
	// A valid path has at most 64 TTLs and ten traced flows. The cap also
	// protects legacy imported snapshots that lacked those input bounds.
	const maxAddresses = 640
	items := make([]pathEntityHop, 0)
	addresses := make([]string, 0)
	seen := make(map[string]bool)
	canonical := make(map[string]string)
	truncated := false
	for _, hop := range p.Hops {
		for _, node := range hop.Nodes {
			if node.IP == "" {
				continue
			}
			if len(items) >= maxAddresses {
				truncated = true
				continue
			}
			if alias, aliasErr := (entity.AliasKey{Kind: entity.AddressAlias, Value: node.IP}).Normalize(); aliasErr == nil {
				canonical[node.IP] = alias.Value
				if !seen[alias.Value] {
					seen[alias.Value] = true
					addresses = append(addresses, alias.Value)
				}
			}
			items = append(items, pathEntityHop{TTL: hop.TTL, IP: node.IP})
		}
	}
	resolved, err := registry.ResolveAddresses(ctx, scope, addresses)
	if err != nil {
		return entityAPIError(err)
	}
	for _, resolution := range resolved {
		if err := s.authorizeEntityResolution(r.Context(), principal, resolution, resource); err != nil {
			return err
		}
	}
	for i := range items {
		items[i].Resolution = entity.Resolution{Scope: scope,
			Alias:  entity.AliasKey{Kind: entity.AddressAlias, Value: items[i].IP},
			Status: entity.Unresolved}
		if key, ok := canonical[items[i].IP]; ok {
			items[i].Resolution = resolved[key]
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"test_id": r.PathValue("id"), "context_id": scope.ContextID,
		"status": "current", "coverage": "registered_sources_only", "items": items, "truncated": truncated,
	})
	return nil
}
