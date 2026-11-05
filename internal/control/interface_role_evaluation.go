// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"regexp"
	"regexp/syntax"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// evaluateInterfaceRoleConfiguration bridges a complete owned configuration
// snapshot to the existing evidence classifier. It has no identity authority:
// the storage caller must establish current canonical interface/source access.
// Nothing is published when any definition, scope or resource admission fails.
func evaluateInterfaceRoleConfiguration(ctx context.Context, facts interfaceRoleFacts, record entity.InterfaceRolePolicyRecord,
	override *entity.InterfaceRoleOverrideRecord, description string, at time.Time,
	prefixes []interfaceRoleIXPrefix, budget interfaceRoleBudget) (interfaceRoleDecision, error) {
	none := interfaceRoleDecision{}
	policy, err := interfaceRoleConfiguredPolicy(ctx, facts, &record, override, &budget)
	if err != nil {
		return none, err
	}
	if !utf8.ValidString(description) || !interfaceRoleAssociationID(facts.InterfaceID) || at.IsZero() {
		return none, errInterfaceRoleInput
	}
	if err := validateInterfaceRoleSourcePresence(facts); err != nil {
		return none, err
	}
	if err := validateInterfaceRoleInputs(ctx, facts.Scope, facts, policy, prefixes, &budget); err != nil {
		return none, err
	}
	if err := budget.charge(ctx, len(description), 4, 1); err != nil {
		return none, err
	}
	// An owned override survives withdrawn observations. Never manufacture a
	// description match (or clock) from missing/inactive/stale source evidence.
	if policy.Override == nil && facts.SourceActive && facts.Clock.current(at) {
		match, err := matchInterfaceRoleDescription(ctx, record, facts, description, &budget)
		if err != nil {
			return none, err
		}
		if match != nil {
			policy.Rules = []interfaceRoleRuleMatch{*match}
		}
	}
	return classifyInterfaceRole(ctx, facts.Scope, at, facts, policy, prefixes, budget)
}

func interfaceRoleConfigurationVersion(id, revision string) (string, error) {
	version, err := strconv.ParseInt(revision, 10, 64)
	if err != nil || version < 0 || strconv.FormatInt(version, 10) != revision ||
		(version == 0 && id != "") || (version > 0 && !interfaceRoleAssociationID(id)) {
		return "", errInterfaceRoleInput
	}
	if version == 0 {
		return "", nil
	}
	return id + "/" + revision, nil
}

func interfaceRoleConfiguredPolicy(ctx context.Context, facts interfaceRoleFacts, record *entity.InterfaceRolePolicyRecord,
	override *entity.InterfaceRoleOverrideRecord, budget *interfaceRoleBudget) (interfaceRolePolicy, error) {
	none := interfaceRolePolicy{}
	scope, err := facts.Scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || tenant.String() != scope.TenantID || scope != facts.Scope || record.Scope != scope ||
		(override != nil && (override.Scope != scope || override.InterfaceID != facts.InterfaceID)) {
		return none, entity.ErrScopeMismatch
	}
	version, err := interfaceRoleConfigurationVersion(record.ID, record.Revision)
	if err != nil {
		return none, err
	}
	if version == "" && (len(record.Definition.ProviderASNs)+len(record.Definition.CustomerASNs)+len(record.Definition.DescriptionRules) != 0 || !record.UpdatedAt.IsZero()) {
		return none, errInterfaceRoleInput
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return none, errInterfaceRoleBudget
	}
	// Reserve one half for complete normalization/parser trees and owned input
	// copies. The remainder admits compiled regexes, matches and final evidence.
	normalization := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 2}
	definition, err := entity.NormalizeInterfaceRolePolicy(ctx, record.Definition, normalization)
	if err != nil {
		if errors.Is(err, entity.ErrInterfaceRoleBudget) {
			return none, errInterfaceRoleBudget
		}
		return none, err
	}
	budget.MemoryBytes -= normalization.MemoryBytes
	budget.WorkUnits -= normalization.WorkUnits
	record.Definition = definition
	policy := interfaceRolePolicy{Scope: scope}
	for _, group := range []struct {
		asns []uint32
		role interfaceRole
	}{{definition.ProviderASNs, interfaceRoleTransit}, {definition.CustomerASNs, interfaceRoleCustomer}} {
		if err := budget.charge(ctx, len(group.asns), 256, 1); err != nil {
			return none, err
		}
		for _, asn := range group.asns {
			policy.Declarations = append(policy.Declarations, interfaceRoleDeclaration{Scope: scope, ASN: asn, Role: group.role, SourceID: "policy/" + version})
		}
	}
	if override != nil {
		version, err := interfaceRoleConfigurationVersion(override.ID, override.Revision)
		if err != nil || version == "" || !interfaceRoleValid(override.Role) {
			return none, errInterfaceRoleInput
		}
		if err := budget.charge(ctx, 1, 1024, 1); err != nil {
			return none, err
		}
		policy.Override = &interfaceRoleOverride{Scope: scope, InterfaceID: facts.InterfaceID, Role: override.Role, SourceID: "override/" + version}
	}
	return policy, nil
}

func matchInterfaceRoleDescription(ctx context.Context, record entity.InterfaceRolePolicyRecord, facts interfaceRoleFacts,
	description string, budget *interfaceRoleBudget) (*interfaceRoleRuleMatch, error) {
	for _, rule := range record.Definition.DescriptionRules {
		if err := budget.charge(ctx, len(rule.Pattern), 128, 1); err != nil {
			return nil, err
		}
		tree, err := syntax.Parse(rule.Pattern, syntax.Perl)
		if err != nil {
			return nil, errInterfaceRoleInput
		}
		if err := admitInterfaceRoleRegexp(ctx, tree, description, budget); err != nil {
			return nil, err
		}
		compiled, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, errInterfaceRoleInput
		}
		matched := compiled.MatchString(description)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if matched {
			return &interfaceRoleRuleMatch{Scope: facts.Scope, InterfaceID: facts.InterfaceID, FactSourceID: facts.SourceID,
				RuleID: "policy/" + record.ID + "/" + record.Revision + "/rule/" + rule.ID, Role: rule.Role, Matched: true}, nil
		}
	}
	return nil, ctx.Err()
}

// syntax.Parse retains repeat nodes: a short pattern can expand into a large
// executable. Bound the full expansion BEFORE regexp.Compile, and charge both
// capture-state memory and worst-case linear matching work before MatchString.
// These accounting units are conservative admission, not measured RSS/time.
func admitInterfaceRoleRegexp(ctx context.Context, tree *syntax.Regexp, description string, budget *interfaceRoleBudget) error {
	limit := budget.MemoryBytes / 256
	states, err := interfaceRoleRegexpStates(ctx, tree, limit)
	if err != nil {
		return err
	}
	captures := int64(tree.MaxCap())*2 + 2
	if states > budget.MemoryBytes/256 || captures > budget.MemoryBytes/64 ||
		states > budget.MemoryBytes/(captures*64) {
		return errInterfaceRoleBudget
	}
	if err := budget.charge(ctx, int(states), 256+captures*64, 1); err != nil {
		return err
	}
	characters := int64(utf8.RuneCountInString(description)) + 1
	if characters > budget.WorkUnits/captures || states > budget.WorkUnits/(characters*captures) {
		return errInterfaceRoleBudget
	}
	return budget.charge(ctx, int(states), 1, characters*captures)
}

func interfaceRoleRegexpStates(ctx context.Context, tree *syntax.Regexp, limit int64) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	states := int64(2 + len(tree.Rune))
	if states > limit {
		return 0, errInterfaceRoleBudget
	}
	for _, child := range tree.Sub {
		n, err := interfaceRoleRegexpStates(ctx, child, limit-states)
		if err != nil {
			return 0, err
		}
		copies := int64(1)
		if tree.Op == syntax.OpRepeat {
			copies = int64(tree.Max)
			if tree.Max < 0 {
				copies = int64(tree.Min) + 1
			}
			// Two branch instructions per optional/unbounded repetition.
			n += 2
		}
		if n > 0 && copies > (limit-states)/n {
			return 0, errInterfaceRoleBudget
		}
		states += n * copies
	}
	return states, nil
}
