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
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type interfaceRole string

const (
	interfaceRoleTransit  interfaceRole = "transit"
	interfaceRoleIX       interfaceRole = "ix_peering"
	interfaceRolePrivate  interfaceRole = "private_peering"
	interfaceRoleCustomer interfaceRole = "customer"
	interfaceRoleBackbone interfaceRole = "backbone"
	interfaceRoleOther    interfaceRole = "other"
)

var (
	errInterfaceRoleInput  = errors.New("interface role evidence is invalid")
	errInterfaceRoleBudget = errors.New("interface role budget exceeded")
)

type interfaceRoleClock struct{ ObservedAt, ValidUntil time.Time }

func (c interfaceRoleClock) current(at time.Time) bool {
	return !c.ObservedAt.IsZero() && !c.ObservedAt.After(at) && c.ValidUntil.After(at)
}
func (c interfaceRoleClock) valid() bool {
	return !c.ObservedAt.IsZero() && c.ValidUntil.After(c.ObservedAt)
}

type interfaceRolePeer struct {
	Scope                 entity.Scope
	InterfaceID, SourceID string
	ASN                   uint32
	// Current verified producer/certificate binding.
	SourceActive bool
	Clock        interfaceRoleClock
	// Current prefix and canonical-binding provenance, when association was
	// needed. These are owned snapshot references, not client-supplied joins.
	AssociationSources []string
}
type interfaceRoleIXPrefix struct {
	SourceID string
	Prefix   netip.Prefix
	Clock    interfaceRoleClock
}
type interfaceRoleDeclaration struct {
	Scope    entity.Scope
	ASN      uint32
	Role     interfaceRole
	SourceID string
}

// Rule matches are produced by the caller's bounded current description-rule
// evaluator. They are not client claims or a second regular-expression engine.
type interfaceRoleRuleMatch struct {
	Scope                             entity.Scope
	InterfaceID, RuleID, FactSourceID string
	Role                              interfaceRole
	Matched                           bool
}
type interfaceRoleOverride struct {
	Scope                 entity.Scope
	InterfaceID, SourceID string
	Role                  interfaceRole
}
type interfaceRoleFacts struct {
	Scope                 entity.Scope
	InterfaceID, SourceID string
	Clock                 interfaceRoleClock
	// Current verified interface source binding.
	SourceActive bool
	Addresses    []netip.Addr
	Peers        []interfaceRolePeer
}
type interfaceRolePolicy struct {
	Scope        entity.Scope
	Declarations []interfaceRoleDeclaration
	Rules        []interfaceRoleRuleMatch // explicit operator order
	Override     *interfaceRoleOverride
}
type interfaceRoleDecision struct {
	Scope       entity.Scope
	InterfaceID string
	Role        interfaceRole
	Reason      string
	Sources     []string
	AsOf        time.Time
}
type interfaceRoleBudget struct{ MemoryBytes, WorkUnits int64 }

func (b *interfaceRoleBudget) charge(ctx context.Context, count int, bytesEach, workEach int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n := int64(count)
	if count < 0 || bytesEach <= 0 || workEach <= 0 || n > b.MemoryBytes/bytesEach || n > b.WorkUnits/workEach {
		return errInterfaceRoleBudget
	}
	b.MemoryBytes -= n * bytesEach
	b.WorkUnits -= n * workEach
	return nil
}
func interfaceRoleValid(role interfaceRole) bool {
	return slices.Contains([]interfaceRole{interfaceRoleTransit, interfaceRoleIX, interfaceRolePrivate, interfaceRoleCustomer, interfaceRoleBackbone, interfaceRoleOther}, role)
}
func interfaceRoleSource(id string) bool {
	return id != "" && strings.TrimSpace(id) == id && len(id) <= 1024 && utf8.ValidString(id) && strings.IndexFunc(id, unicode.IsControl) < 0
}

// classifyInterfaceRole combines already authenticated, current, owned facts.
// It performs no IO, stores nothing and grants no identity, lifecycle or RBAC
// authority. The shipping caller must first load these immutable inputs through
// its tenant/RLS boundary and account for their lifetime plus rule evaluation.
func classifyInterfaceRole(ctx context.Context, scope entity.Scope, at time.Time, facts interfaceRoleFacts, policy interfaceRolePolicy, prefixes []interfaceRoleIXPrefix, budget interfaceRoleBudget) (interfaceRoleDecision, error) {
	none := interfaceRoleDecision{}
	normalized, err := scope.Normalize()
	bound, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || bound.String() != normalized.TenantID || facts.Scope != normalized || policy.Scope != normalized {
		return none, entity.ErrScopeMismatch
	}
	id, err := gouuid.Parse(facts.InterfaceID)
	if err != nil || id == gouuid.Nil || id.String() != facts.InterfaceID || !interfaceRoleSource(facts.SourceID) || !facts.Clock.valid() || at.IsZero() {
		return none, errInterfaceRoleInput
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return none, errInterfaceRoleBudget
	}
	if err := budget.charge(ctx, 1, 4096, 1); err != nil {
		return none, err
	}
	if err := validateInterfaceRoleInputs(ctx, normalized, facts, policy, prefixes, &budget); err != nil {
		return none, err
	}
	result := interfaceRoleDecision{Scope: normalized, InterfaceID: facts.InterfaceID, Role: interfaceRoleOther, Reason: "insufficient_evidence", AsOf: at}
	if override := policy.Override; override != nil {
		result.Role, result.Reason, result.Sources = override.Role, "operator_override", []string{strings.Clone(override.SourceID)}
		return finishInterfaceRoleDecision(ctx, result)
	}
	if !facts.SourceActive || !facts.Clock.current(at) {
		return finishInterfaceRoleDecision(ctx, result)
	}
	for _, rule := range policy.Rules {
		if err := budget.charge(ctx, 1, 1, 1); err != nil {
			return none, err
		}
		if rule.Matched {
			result.Role, result.Reason, result.Sources = rule.Role, "description_rule", []string{strings.Clone(rule.RuleID), strings.Clone(facts.SourceID)}
			return finishInterfaceRoleDecision(ctx, result)
		}
	}
	roles := map[interfaceRole]bool{}
	sources := map[string]bool{}
	add := func(role interfaceRole, refs ...string) error {
		for _, ref := range refs {
			if sources[ref] {
				continue
			}
			if err := budget.charge(ctx, len(ref)+128, 2, 1); err != nil {
				return err
			}
			sources[strings.Clone(ref)] = true
		}
		roles[role] = true
		return nil
	}
	for _, prefix := range prefixes {
		if !prefix.Clock.current(at) {
			continue
		}
		for _, address := range facts.Addresses {
			if err := budget.charge(ctx, 1, 1, 1); err != nil {
				return none, err
			}
			if prefix.Prefix.Contains(address.Unmap()) {
				if err := add(interfaceRoleIX, prefix.SourceID, facts.SourceID); err != nil {
					return none, err
				}
			}
		}
	}
	for _, peer := range facts.Peers {
		if !peer.SourceActive || !peer.Clock.current(at) {
			continue
		}
		for _, declaration := range policy.Declarations {
			if err := budget.charge(ctx, 1, 1, 1); err != nil {
				return none, err
			}
			if peer.ASN == declaration.ASN {
				if err := add(declaration.Role, facts.SourceID, peer.SourceID, declaration.SourceID); err != nil {
					return none, err
				}
				for _, source := range peer.AssociationSources {
					if err := budget.charge(ctx, 1, 1, 1); err != nil {
						return none, err
					}
					if err := add(declaration.Role, source); err != nil {
						return none, err
					}
				}
			}
		}
	}
	for source := range sources {
		result.Sources = append(result.Sources, source)
	}
	slices.Sort(result.Sources)
	switch len(roles) {
	case 0:
	case 1:
		for role := range roles {
			result.Role = role
		}
		result.Reason = "current_evidence"
	default:
		result.Reason = "conflicting_evidence"
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return result, nil
}

func validateInterfaceRoleInputs(ctx context.Context, scope entity.Scope, facts interfaceRoleFacts, policy interfaceRolePolicy, prefixes []interfaceRoleIXPrefix, budget *interfaceRoleBudget) error {
	for _, count := range []int{len(facts.Addresses), len(facts.Peers), len(policy.Declarations), len(policy.Rules), len(prefixes)} {
		if err := budget.charge(ctx, count, 256, 1); err != nil {
			return err
		}
	}
	for _, address := range facts.Addresses {
		if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return errInterfaceRoleInput
		}
	}
	for _, peer := range facts.Peers {
		if peer.Scope != scope || peer.InterfaceID != facts.InterfaceID {
			return entity.ErrScopeMismatch
		}
		if peer.ASN == 0 || !interfaceRoleSource(peer.SourceID) || !peer.Clock.valid() {
			return errInterfaceRoleInput
		}
		if err := budget.charge(ctx, len(peer.AssociationSources), 1024, 1); err != nil {
			return err
		}
		for _, source := range peer.AssociationSources {
			if !interfaceRoleSource(source) {
				return errInterfaceRoleInput
			}
		}
	}
	declarations := map[uint32]interfaceRole{}
	for _, declaration := range policy.Declarations {
		if declaration.Scope != scope {
			return entity.ErrScopeMismatch
		}
		if declaration.ASN == 0 || !interfaceRoleSource(declaration.SourceID) || declaration.Role != interfaceRoleTransit && declaration.Role != interfaceRoleCustomer {
			return errInterfaceRoleInput
		}
		if previous, ok := declarations[declaration.ASN]; ok && previous != declaration.Role {
			return errInterfaceRoleInput
		}
		declarations[declaration.ASN] = declaration.Role
	}
	for _, rule := range policy.Rules {
		if rule.Scope != scope || rule.InterfaceID != facts.InterfaceID || rule.FactSourceID != facts.SourceID {
			return entity.ErrScopeMismatch
		}
		if !interfaceRoleValid(rule.Role) || !interfaceRoleSource(rule.RuleID) {
			return errInterfaceRoleInput
		}
	}
	if override := policy.Override; override != nil {
		if override.Scope != scope || override.InterfaceID != facts.InterfaceID {
			return entity.ErrScopeMismatch
		}
		if !interfaceRoleValid(override.Role) || !interfaceRoleSource(override.SourceID) {
			return errInterfaceRoleInput
		}
	}
	for _, prefix := range prefixes {
		if !prefix.Prefix.IsValid() || prefix.Prefix.Bits() == 0 || prefix.Prefix.Addr().IsMulticast() || prefix.Prefix != prefix.Prefix.Masked() || prefix.Prefix.Addr().Is4In6() || !interfaceRoleSource(prefix.SourceID) || !prefix.Clock.valid() {
			return errInterfaceRoleInput
		}
	}
	// Source text and immutable IDs remain input-owned. Charge copied result
	// references separately before adding them to the returned explanation.
	return ctx.Err()
}

func finishInterfaceRoleDecision(ctx context.Context, result interfaceRoleDecision) (interfaceRoleDecision, error) {
	if err := ctx.Err(); err != nil {
		return interfaceRoleDecision{}, err
	}
	return result, nil
}
