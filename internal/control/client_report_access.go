// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"sync"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type clientReportAccessKey struct{}
type clientReportAccessRequirement struct {
	Permission string            `json:"permission"`
	Resource   map[string]string `json:"resource"`
}

// The operation records successful checks as requirements, never decisions or
// principals. A future reader must independently satisfy every current check.
type clientReportAccessCapture struct {
	mu           sync.Mutex
	tenant       string
	remaining    int64
	seen         map[string]bool
	requirements []clientReportAccessRequirement
}

func (c *clientReportAccessCapture) record(p *auth.Principal, permission string, mode auth.RBACCheck, resource map[string]string) error {
	if p == nil || p.TenantID != c.tenant || resource[auth.ResourceTenantKey] != c.tenant || mode != auth.RBACGlobal || !clientReportSourcePermission(permission) {
		return apierror.Forbidden("monthly report source access requirements are invalid")
	}
	item := clientReportAccessRequirement{Permission: permission, Resource: maps.Clone(resource)}
	raw, err := json.Marshal(item)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := string(raw)
	if c.seen[key] {
		return nil
	}
	cost := int64(1024 + 16*len(raw))
	if cost > c.remaining {
		return store.ErrClientReportBudget
	}
	c.remaining -= cost
	c.seen[key] = true
	c.requirements = append(c.requirements, item)
	return nil
}

func clientReportSourcePermission(permission string) bool {
	return slices.Contains([]string{permTestRead, permIncidentRead, permChangeRead, permFlowRead, permTagsRead, permAIQuery, "entities.read", "metrics.read", "events.read", "agent.read"}, permission)
}

func (s *Server) revalidateClientReportAccessScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, requirements []clientReportAccessRequirement) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || actor == nil || actor.UserID == "" || actor.TenantID != bound.String() || len(requirements) == 0 {
		return errReportSourceRequirements
	}
	current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
	if err != nil {
		return err
	}
	ctx, principal, err := current.requestContext(ctx, actor)
	if err != nil {
		return err
	}
	for _, item := range requirements {
		if !clientReportSourcePermission(item.Permission) || item.Resource[auth.ResourceTenantKey] != bound.String() {
			return errReportSourceRequirements
		}
		if err := s.authorize(ctx, principal, item.Permission, auth.RBACGlobal, item.Resource); err != nil {
			return err
		}
		if id := item.Resource["context_id"]; id != "" {
			record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, id)
			if err != nil {
				return err
			}
			resource := maps.Clone(item.Resource)
			maps.Copy(resource, entityContextResource(record))
			if err := s.authorize(ctx, principal, item.Permission, auth.RBACGlobal, resource); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
