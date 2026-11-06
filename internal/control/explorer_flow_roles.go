// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type flowRoleSnapshot struct {
	data        *flowstore.InterfaceRoleQueryData
	inputDigest string // complete private inputs, never public source text
}

// The same application-role snapshot reads current user/credential policy,
// complete tenant-wide ownership, then authorized context facts. Source rows
// cannot choose context by AgentID, nor make an unreadable competitor vanish.
func (s *Server) loadFlowRoleSnapshot(ctx context.Context, actor *auth.Principal, budget flowstore.ExplorerBudget) (flowRoleSnapshot, error) {
	none := flowRoleSnapshot{}
	tenant, bound := tenancy.FromContext(ctx)
	if actor == nil || actor.TenantID == "" || actor.UserID == "" || !bound || tenant.String() != actor.TenantID {
		return none, apierror.Forbidden("current tenant user is required for interface roles")
	}
	if s.pool == nil || budget.Validate() != nil {
		return none, apierror.Unavailable("current interface role storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("current interface role tenant is inactive")
	}
	var projections []flowstore.InterfaceRoleProjection
	var digest []byte
	var at time.Time
	// Both source reads together reserve half the operation. Each source read
	// partitions that share between catalogue, inputs, evaluation and output.
	limit := budget.MemoryBytes / 8
	readBudget := entity.InterfaceRolePolicyBudget{MemoryBytes: limit, WorkUnits: limit / 2}
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorizeNativeFlow(ctx, principal); err != nil {
			return err
		}
		for _, permission := range []string{ai.PermEntitiesRead, "metrics.read", "events.read"} {
			if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID}); err != nil {
				return err
			}
		}
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&at); err != nil {
			return err
		}
		reader := store.NewInterfaceRoleInputs(s.pool)
		contextRecords, contextAllowed := map[string]entity.ContextRecord{}, map[string]bool{}
		owners, err := reader.ExporterOwnersInScope(ctx, sc, readBudget)
		if err != nil {
			return err
		}
		digest, err = hashFlowRoleInputs(ctx, digest, owners, limit)
		if err != nil {
			return err
		}
		perOwner := limit / int64(max(1, len(owners)))
		for _, owner := range owners {
			record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, owner.ContextID)
			if err != nil {
				return err
			}
			allowed := true
			for _, permission := range []string{permAIQuery, permFlowRead, ai.PermEntitiesRead, "metrics.read", "events.read"} {
				decision, err := s.decide(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record))
				if err != nil {
					return err
				}
				allowed = allowed && decision == auth.DecisionAllowed
			}
			digest, err = hashFlowRoleInputs(ctx, digest, struct {
				Context entity.ContextRecord
				Allowed bool
			}{record, allowed}, perOwner)
			if err != nil {
				return err
			}
			if !allowed || owner.RouterID == "" {
				continue
			}
			contextRecords[record.ContextID], contextAllowed[record.ContextID] = record, true
			part := entity.InterfaceRolePolicyBudget{MemoryBytes: perOwner / 4, WorkUnits: perOwner / 8}
			bindings, err := reader.FlowBindingsInScope(ctx, sc, owner.Scope, part)
			if err != nil {
				return err
			}
			digest, err = hashFlowRoleInputs(ctx, digest, bindings, perOwner/4)
			if err != nil {
				return err
			}
			interfaces, err := reader.RouterInterfacesInScope(ctx, sc, owner.Scope, owner.RouterID, part)
			if err != nil {
				return err
			}
			// Interface inputs are evaluated sequentially and released. Reuse
			// their peak memory share; divide aggregate work, not the capacity
			// for a complete saved policy, by the interface population.
			perInterface := budget.MemoryBytes / 4
			perInterfaceWork := perOwner / (4 * int64(max(1, len(interfaces))))
			byIndex, ambiguous := map[uint32][]flowstore.InterfaceRoleProjection{}, map[uint32]bool{}
			for _, id := range interfaces {
				inputs, err := reader.LoadInScope(ctx, sc, owner.Scope, id, entity.InterfaceRolePolicyBudget{MemoryBytes: perInterface, WorkUnits: perInterfaceWork})
				if err != nil {
					return err
				}
				// The transaction time advances on publication re-read, while
				// every source/configuration value and clock must still agree.
				facts := inputs
				facts.AsOf = time.Time{}
				digest, err = hashFlowRoleInputs(ctx, digest, facts, perInterface)
				if err != nil {
					return err
				}
				if inputs.RouterID != owner.RouterID || inputs.SNMP == nil || inputs.IfIndex == 0 {
					continue
				}
				decision, err := explainInterfaceRoleInputs(ctx, inputs, nil, interfaceRoleBudget{MemoryBytes: perInterface, WorkUnits: perInterfaceWork})
				if err != nil {
					return err
				}
				if _, exists := byIndex[inputs.IfIndex]; exists || ambiguous[inputs.IfIndex] {
					delete(byIndex, inputs.IfIndex)
					ambiguous[inputs.IfIndex] = true
					continue
				}
				var selected []flowstore.InterfaceRoleProjection
				for _, binding := range bindings {
					if binding.AgentID != owner.AgentID || binding.RouterID != owner.RouterID || binding.Exporter != owner.Exporter {
						continue
					}
					until := inputs.SNMP.ValidUntil
					if binding.ValidUntil.Before(until) {
						until = binding.ValidUntil
					}
					for _, source := range inputs.SNMP.Bindings {
						if source.ValidUntil.Before(until) {
							until = source.ValidUntil
						}
					}
					for _, peer := range inputs.Peers {
						if peer.ValidUntil.Before(until) {
							until = peer.ValidUntil
						}
					}
					if inputs.SNMP.Prefixes != nil && inputs.SNMP.PrefixClock.ValidUntil.Before(until) {
						until = inputs.SNMP.PrefixClock.ValidUntil
					}
					sources := append(slices.Clone(decision.Sources), binding.SourceID, inputs.SNMP.SourceID)
					selected = append(selected, flowstore.InterfaceRoleProjection{Scope: owner.Scope, RouterID: owner.RouterID, InterfaceID: id,
						Exporter: owner.Exporter.String(), Protocol: binding.Protocol, Domain: binding.Domain, IfIndex: inputs.IfIndex,
						Role: decision.Role, Reason: decision.Reason, Sources: sources, ValidUntil: until})
				}
				byIndex[inputs.IfIndex] = selected
			}
			indices := make([]uint32, 0, len(byIndex))
			for index := range byIndex {
				indices = append(indices, index)
			}
			slices.Sort(indices)
			for _, index := range indices {
				projections = append(projections, byIndex[index]...)
			}
		}
		records := make([]entity.ContextRecord, 0, len(contextRecords))
		for _, record := range contextRecords {
			records = append(records, record)
		}
		slices.SortFunc(records, func(a, b entity.ContextRecord) int {
			if a.ContextID < b.ContextID {
				return -1
			}
			if a.ContextID > b.ContextID {
				return 1
			}
			return 0
		})
		return captureReportRoleContextRequirements(ctx, principal, records, contextAllowed)
	})
	if err != nil {
		return none, interfaceRoleAPIError(err)
	}
	data, err := flowstore.NewInterfaceRoleQueryData(ctx, actor.TenantID, at, projections, budget.MemoryBytes/8)
	if err != nil {
		return none, flowExplorerStoreError(err)
	}
	return flowRoleSnapshot{data: data, inputDigest: hex.EncodeToString(digest)}, nil
}

func hashFlowRoleInputs(ctx context.Context, previous []byte, value any, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if int64(len(body)+len(previous)) > limit {
		return nil, entity.ErrInterfaceRoleBudget
	}
	return crypto.Hash(append(previous, body...)), nil
}
