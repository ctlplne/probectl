// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type topologyFailureLink struct {
	original   store.ClientReportPhysicalLink
	fromDevice string
	port       store.DeviceCounterInterface
}

type topologyFailureInterfaceKey struct {
	device string
	index  uint32
}

type topologyFailureSourcePlan struct {
	links    []topologyFailureLink
	bindings []store.InterfaceRoleFlowBinding
}

type topologyFailureAuthorize func(context.Context, entity.ContextRecord, string) error

// readTopologyFailureSources builds a request-local source catalog. Both
// endpoint devices and the canonical interface need current read grants. The
// physical receipt supplies the interface index. Exporter registrations are
// checked across the tenant before any binding from the selected routing
// context can be used to select rows.
func (s *Server) readTopologyFailureSources(ctx context.Context, actor *auth.Principal, scope entity.Scope, budget flowstore.ExplorerBudget) (topologyFailureSourcePlan, error) {
	var out topologyFailureSourcePlan
	err := s.withTopologyFailureSnapshot(ctx, actor, scope, budget, func(ctx context.Context, sc tenancy.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize) error {
		originals, err := store.NewEntityRegistry(s.pool).CurrentPhysicalLinksInContext(ctx, sc, scope, budget.MemoryBytes/8,
			func(ctx context.Context, record entity.ContextRecord, from, to string) error {
				if err := authorize(ctx, record, from); err != nil {
					return err
				}
				return authorize(ctx, record, to)
			})
		if err != nil {
			return err
		}
		ports := map[string]store.DeviceCounterInterface{}
		devices := map[string]bool{}
		counters := store.NewDeviceCounterCaptures(s.pool)
		for _, link := range originals {
			key := link.FromEntityID
			port, read := ports[key]
			if !read {
				// The physical receipt begins at the local interface. Resolve
				// its current parent before matching the graph's device nodes.
				port, err = counters.CurrentInterfaceInScope(ctx, sc, scope, key)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				if port.InterfaceID != "" {
					if err := authorize(ctx, record, port.Source.DeviceID); err != nil {
						return err
					}
				}
				ports[key] = port
			}
			fromDevice := port.Source.DeviceID
			if port.IfIndex != link.LocalIfIndex || link.ObservedAt.Before(port.CreatedAt) || link.ObservedAt.Before(port.Source.SourceAssignedAt) ||
				link.ObservedAt.Before(port.Source.AgentAssignedAt) {
				port = store.DeviceCounterInterface{}
			}
			// Keep independent physical links even when their counter
			// interface is absent. Missing coverage cannot select a route.
			out.links = append(out.links, topologyFailureLink{original: link, fromDevice: fromDevice, port: port})
			devices[fromDevice], devices[link.ToEntityID] = true, true
		}
		inputs := &store.InterfaceRoleInputsStore{}
		roleBudget := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.ReadBytes / 8}
		owners, err := inputs.ExporterOwnersInScope(ctx, sc, roleBudget)
		if err != nil {
			return err
		}
		byExporter := make(map[netip.Addr][]store.InterfaceRoleExporterOwner)
		for _, owner := range owners {
			byExporter[owner.Exporter] = append(byExporter[owner.Exporter], owner)
		}
		bindings, err := inputs.FlowBindingsInScope(ctx, sc, scope, roleBudget)
		if err != nil {
			return err
		}
		for _, binding := range bindings {
			owner := byExporter[binding.Exporter]
			if !devices[binding.RouterID] || len(owner) != 1 || owner[0].Scope != binding.Scope ||
				owner[0].RouterID != binding.RouterID || owner[0].AgentID != binding.AgentID {
				continue
			}
			out.bindings = append(out.bindings, binding)
		}
		return ctx.Err()
	})
	if err != nil {
		return topologyFailureSourcePlan{}, err
	}
	return out, ctx.Err()
}

func (s *Server) withTopologyFailureSnapshot(ctx context.Context, actor *auth.Principal, scope entity.Scope, budget flowstore.ExplorerBudget,
	read func(context.Context, tenancy.Scope, entity.ContextRecord, topologyFailureAuthorize) error) error {
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return err
	}
	normalized, err := scope.Normalize()
	if err != nil || normalized != scope || scope.TenantID != actor.TenantID {
		return entity.ErrScopeMismatch
	}
	if s.pool == nil || budget.Validate() != nil {
		return apierror.Unavailable("traffic failure source admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return err
	}
	if status != "active" || s.requireMFA && !actor.MFASatisfied {
		return apierror.Forbidden("current tenant and authentication required for the traffic model")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, scope.ContextID)
		if err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, entityID string) error {
			if record.TenantID != scope.TenantID || record.ContextID != scope.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			if entityID != "" {
				resource["entity_id"] = entityID
			}
			for _, permission := range []string{ai.PermTopologyRead, permFlowRead, ai.PermEntitiesRead, ai.PermMetricsRead, "events.read"} {
				if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, resource); err != nil {
					return err
				}
			}
			return nil
		}
		if err := authorize(ctx, record, ""); err != nil {
			return err
		}
		return read(ctx, sc, record, authorize)
	})
}
