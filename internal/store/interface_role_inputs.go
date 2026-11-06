// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// InterfaceRoleInputs owns one tenant/context/interface snapshot, not a grant.
// The caller must authorize all selected source planes and revalidate current
// disclosure authority before publication. No global cache or retained state.
type InterfaceRoleInputs struct {
	Scope       entity.Scope
	InterfaceID string
	RouterID    string
	IfIndex     uint32
	AsOf        time.Time
	Policy      entity.InterfaceRolePolicyRecord
	Override    *entity.InterfaceRoleOverrideRecord
	SNMP        *InterfaceRoleSNMPInputs
	Peers       []InterfaceRolePeerInput
}

// InterfaceRoleEvidenceClock intersects observation and current binding expiry.
type InterfaceRoleEvidenceClock struct {
	ObservedAt time.Time
	ValidUntil time.Time
}

// InterfaceRoleSNMPInputs contains one current, complete poll's owned facts.
type InterfaceRoleSNMPInputs struct {
	InterfaceRoleEvidenceClock
	SourceID       string
	PrefixSourceID string
	PrefixClock    InterfaceRoleEvidenceClock
	Description    string
	Addresses      []netip.Addr
	// Nil is unavailable. An empty/partial prefix set is never a clear.
	Prefixes []entity.SNMPInterfacePrefix
	Bindings []InterfaceRoleBindingInput
}

// InterfaceRoleBindingInput maps a current source index to an owned interface.
type InterfaceRoleBindingInput struct {
	InterfaceRoleEvidenceClock
	InterfaceID string
	SourceID    string
	IfIndex     uint32
}

// InterfaceRolePeerInput describes a current observation, not session health.
type InterfaceRolePeerInput struct {
	InterfaceRoleEvidenceClock
	SourceID string
	Address  netip.Addr
	ASN      uint32
}

// InterfaceRoleInputsStore reads current role inputs without caching authority.
type InterfaceRoleInputsStore struct{ pool *pgxpool.Pool }

// NewInterfaceRoleInputs binds the reader to the deployment's tenant router.
func NewInterfaceRoleInputs(pool *pgxpool.Pool) *InterfaceRoleInputsStore {
	return &InterfaceRoleInputsStore{pool: pool}
}

type roleInputAdmission struct{ memory, work int64 }

func (b *roleInputAdmission) charge(ctx context.Context, bytes, work int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if bytes < 0 || work < 0 || bytes > b.memory || work > b.work {
		return entity.ErrInterfaceRoleBudget
	}
	b.memory -= bytes
	b.work -= work
	return nil
}

// Load uses FORCE RLS, the current tenant router, one REPEATABLE READ time and
// transaction-wide silo relation locks. Raw IP/ifIndex never chooses ownership.
// Missing automatic observations preserve an owned manual override; absent or
// foreign canonical interfaces fail closed before reading any source facts.
func (s *InterfaceRoleInputsStore) Load(ctx context.Context, scope entity.Scope, interfaceID string, budget entity.InterfaceRolePolicyBudget) (InterfaceRoleInputs, error) {
	none := InterfaceRoleInputs{}
	want, err := scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || tenant.String() != want.TenantID {
		return none, entity.ErrScopeMismatch
	}
	id, err := validRegistryUUID(interfaceID)
	if err != nil {
		return none, err
	}
	if s == nil || s.pool == nil {
		return none, ErrEntityRegistryUnavailable
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return none, entity.ErrInterfaceRoleBudget
	}
	var out InterfaceRoleInputs
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var readErr error
		out, readErr = s.LoadInScope(ctx, sc, want, id, budget)
		return readErr
	})
	if err != nil {
		return none, err
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return out, nil
}

// LoadInScope reuses an already bound application-role read snapshot. Callers
// can authorize the current user/context/source planes in that SAME snapshot
// before any facts are read. It creates no additional connection or grant.
func (s *InterfaceRoleInputsStore) LoadInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, interfaceID string, budget entity.InterfaceRolePolicyBudget) (InterfaceRoleInputs, error) {
	none := InterfaceRoleInputs{}
	want, err := scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || tenant != sc.Tenant || tenant.String() != want.TenantID || sc.Q == nil {
		return none, entity.ErrScopeMismatch
	}
	id, err := validRegistryUUID(interfaceID)
	if err != nil {
		return none, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return none, entity.ErrInterfaceRoleBudget
	}
	out := InterfaceRoleInputs{Scope: want, InterfaceID: id}
	err = func() error {
		var agent, configured string
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp(),COALESCE(parent.id::text,''),
	 COALESCE(node.interface_index,0),COALESCE(node.source_agent_id,''),COALESCE(node.configured_ref,'')
	 FROM entities node LEFT JOIN entities parent ON
	 (parent.tenant_id,parent.context_id,parent.id)=(node.tenant_id,node.context_id,node.parent_entity_id) AND parent.kind='device'
	 WHERE node.tenant_id=$1 AND node.context_id=$2 AND node.id=$3 AND node.kind='interface'`,
			want.TenantID, want.ContextID, id).Scan(&out.AsOf, &out.RouterID, &out.IfIndex, &agent, &configured); err != nil {
			return err
		}
		var err error
		configuration := InterfaceRoleConfiguration{}
		out.Policy, err = configuration.Policy(ctx, sc, want.ContextID,
			entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 2})
		if err != nil {
			return err
		}
		override, err := configuration.Override(ctx, sc, want.ContextID, id)
		if err != nil {
			return err
		}
		if override.ID != "" {
			out.Override = &override
		}
		admission := roleInputAdmission{memory: budget.MemoryBytes - budget.MemoryBytes/2, work: budget.WorkUnits - budget.WorkUnits/2}
		if err := admission.charge(ctx, 4096, 1); err != nil {
			return err
		}
		if out.RouterID == "" || out.IfIndex == 0 || agent == "" || configured == "" {
			return nil
		}
		out.SNMP, err = loadInterfaceRoleSNMPInputs(ctx, sc, out, agent, configured, &admission)
		if err != nil {
			return err
		}
		out.Peers, err = loadInterfaceRolePeerInputs(ctx, sc, out, &admission)
		return err
	}()
	if err != nil {
		return none, err
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return out, nil
}

// Complete current-evidence authorization is reused separately in each query.
// These joins only project conservative expiration from those same bindings.
func interfaceRoleAuthorityJoinsSQL() string {
	return ` JOIN entity_source_contexts source ON
 (source.tenant_id,source.context_id,source.agent_id,source.source_kind,source.source_ref)=
 (e.tenant_id,e.context_id,e.agent_id,e.source_kind,e.configured_ref)
 JOIN entity_agent_contexts assignment ON
 (assignment.tenant_id,assignment.agent_id,assignment.context_id)=(e.tenant_id,e.agent_id,e.context_id)
 JOIN agent_identities sender ON
 (sender.tenant_id,sender.agent_id,sender.serial)=(e.tenant_id,e.agent_id,e.sender_serial)
 LEFT JOIN agent_identities origin ON e.source_kind='bmp_peer' AND
 (origin.tenant_id,origin.agent_id,origin.serial)=(e.tenant_id,e.configured_ref,e.origin_serial) `
}

func interfaceRoleEvidenceExpirySQL() string {
	return `LEAST(COALESCE(e.expires_at,e.observed_at+interval '24 hours'),
 source.expires_at,assignment.expires_at,sender.not_after,origin.not_after)`
}
