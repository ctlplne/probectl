// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"
	"sync"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type configEvidenceKey struct{}

// This state exists only for the admitted request. Original archive metadata
// is evidence; current context grants and the originating credential remain
// independent requirements before model dispatch and publication.
type configEvidenceScope struct {
	server      *Server
	actor       *auth.Principal
	credential  func(context.Context) error
	permissions []string
	mu          sync.Mutex
	refs        map[string]change.Event
}

func newConfigEvidenceScope(s *Server, actor *auth.Principal, credential func(context.Context) error, permissions ...string) *configEvidenceScope {
	return &configEvidenceScope{server: s, actor: actor, credential: credential, permissions: permissions, refs: map[string]change.Event{}}
}

func (s *Server) configEvidenceForRequest(r *http.Request, permissions ...string) *configEvidenceScope {
	actor := auth.PrincipalFrom(r.Context())
	return newConfigEvidenceScope(s, actor, func(ctx context.Context) error {
		current := s.resolvePrincipal(r.WithContext(ctx))
		if current == nil {
			return unauthenticated(r)
		}
		if !auth.SamePrincipalAuthority(actor, current) {
			return apierror.Forbidden("configuration evidence credential authority changed")
		}
		return ctx.Err()
	}, permissions...)
}

func (scope *configEvidenceScope) withContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, configEvidenceKey{}, scope)
}

func (scope *configEvidenceScope) retain(event change.Event) error {
	if (event.Config == nil || event.Config.Binding == nil) && event.Routing == nil {
		return nil
	}
	if scope == nil || scope.actor == nil || event.TenantID != scope.actor.TenantID {
		return entity.ErrScopeMismatch
	}
	scope.mu.Lock()
	defer scope.mu.Unlock()
	if event.Routing != nil {
		if event.Config != nil || event.Routing.Validate() != nil {
			return change.ErrRouteReference
		}
		reference := *event.Routing
		event.Routing = &reference
		scope.refs["routing:"+event.ID] = event
	} else {
		ref := *event.Config
		binding := *ref.Binding
		ref.Binding = &binding
		event.Config = &ref
		scope.refs["config:"+ref.CurrentID] = event
	}
	return nil
}

func (scope *configEvidenceScope) selected() []change.Event {
	scope.mu.Lock()
	defer scope.mu.Unlock()
	refs := make([]change.Event, 0, len(scope.refs))
	for _, ref := range scope.refs {
		refs = append(refs, ref)
	}
	return refs
}

func (scope *configEvidenceScope) check(ctx context.Context) error {
	refs := scope.selected()
	if len(refs) == 0 {
		return ctx.Err()
	}
	if scope.server == nil || scope.server.pool == nil || scope.actor == nil || scope.actor.UserID == "" || scope.credential == nil {
		return apierror.Forbidden("current configuration evidence authority is unavailable")
	}
	s := scope.server
	ctx, err := bindFlowRoleContext(ctx, scope.actor)
	if err != nil {
		return err
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, scope.actor.TenantID)
	if err != nil {
		return err
	}
	if status != "active" {
		return apierror.Forbidden("configuration evidence tenant is inactive")
	}
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, scope.actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, scope.actor)
		if err != nil {
			return err
		}
		permissions := append([]string{ai.PermMetricsRead, ai.PermEntitiesRead}, scope.permissions...)
		var configs, routing []change.Event
		seen := map[[4]string]bool{}
		for _, ref := range refs {
			if ref.Routing != nil {
				routing = append(routing, ref)
				continue
			}
			configs = append(configs, ref)
			binding := ref.Config.Binding
			key := [4]string{binding.ContextID, binding.DeviceEntityID, binding.AgentID, binding.SourceRef}
			if seen[key] {
				continue
			}
			seen[key] = true
			record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, binding.ContextID)
			if err != nil {
				return err
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["agent_id"], resource["source_kind"], resource["source_ref"] = binding.DeviceEntityID, binding.AgentID, string(entity.DeviceTarget), binding.SourceRef
			for _, permission := range permissions {
				if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
					return err
				}
			}
		}
		memory := flowstore.ExplorerOperationBudget(ctx, s.flowStore).MemoryBytes / 8
		if err := (store.ChangeEvents{}).VerifyConfigChangeReferencesInScope(ctx, sc, configs, memory); err != nil {
			return err
		}
		return (store.ChangeEvents{}).VerifyRoutingChangeReferencesInScope(ctx, sc, routing, memory, s.routingChangeAuthorizer(principal, scope.permissions...))
	})
	if err != nil {
		return err
	}
	return scope.credential(ctx)
}

// Explicit canonical selectors can match across renames. Narrow name/address
// queries cannot attach bound archives without the matching original identity.
func configChangeMatches(event change.Event, selectors map[string]string, target, prefix string) bool {
	if event.Routing != nil {
		reference := event.Routing
		if selectors["context_id"] != "" && selectors["context_id"] != reference.ContextID {
			return false
		}
		if selectors["entity_id"] != "" && selectors["entity_id"] != reference.RouterID {
			return false
		}
		if target == "" && prefix == "" {
			return true
		}
		return selectors["context_id"] == reference.ContextID && selectors["entity_id"] == reference.RouterID && changeMatches(event, target, prefix)
	}
	if event.Config == nil || event.Config.Binding == nil {
		return changeMatches(event, target, prefix)
	}
	binding := event.Config.Binding
	if selectors["context_id"] != "" && selectors["context_id"] != binding.ContextID {
		return false
	}
	if selectors["entity_id"] != "" && selectors["entity_id"] != binding.DeviceEntityID {
		return false
	}
	if target == "" && prefix == "" {
		return true
	}
	return selectors["context_id"] == binding.ContextID && selectors["entity_id"] == binding.DeviceEntityID
}
