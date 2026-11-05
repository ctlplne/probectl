// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"context"
	"errors"
	"regexp/syntax"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

type InterfaceRole string

const (
	InterfaceRoleTransit  InterfaceRole = "transit"
	InterfaceRoleIX       InterfaceRole = "ix_peering"
	InterfaceRolePrivate  InterfaceRole = "private_peering"
	InterfaceRoleCustomer InterfaceRole = "customer"
	InterfaceRoleBackbone InterfaceRole = "backbone"
	InterfaceRoleOther    InterfaceRole = "other"
)

var (
	ErrInterfaceRolePolicy   = errors.New("invalid interface role policy")
	ErrInterfaceRoleBudget   = errors.New("interface role resource admission exceeded")
	ErrInterfaceRoleConflict = errors.New("interface role configuration changed")
)

func ValidInterfaceRole(role InterfaceRole) bool {
	switch role {
	case InterfaceRoleTransit, InterfaceRoleIX, InterfaceRolePrivate, InterfaceRoleCustomer, InterfaceRoleBackbone, InterfaceRoleOther:
		return true
	default:
		return false
	}
}

// InterfaceRoleDescriptionRule matches observed interface descriptions in
// explicit operator order. Its ID belongs to this context's policy, never an
// entity/source selector. The writer generates IDs for newly added rules.
type InterfaceRoleDescriptionRule struct {
	ID      string        `json:"id"`
	Pattern string        `json:"pattern"`
	Role    InterfaceRole `json:"role"`
}

type InterfaceRolePolicyDefinition struct {
	ProviderASNs     []uint32                       `json:"provider_asns"`
	CustomerASNs     []uint32                       `json:"customer_asns"`
	DescriptionRules []InterfaceRoleDescriptionRule `json:"description_rules"`
}

// Revision is decimal text on every public surface, preserving bigint CAS
// versions beyond JavaScript's exact-number range. Zero denotes no policy.
type InterfaceRolePolicyRecord struct {
	Scope
	ID         string                        `json:"id"`
	Revision   string                        `json:"revision"`
	Definition InterfaceRolePolicyDefinition `json:"definition"`
	UpdatedAt  time.Time                     `json:"updated_at"`
}

type InterfaceRoleOverrideRecord struct {
	Scope
	InterfaceID string        `json:"interface_id"`
	ID          string        `json:"id"`
	Revision    string        `json:"revision"`
	Role        InterfaceRole `json:"role"`
	UpdatedAt   time.Time     `json:"updated_at"`
}

// The caller supplies positive operation admission, not a rule/ASN count cap.
// These are conservative input/parser accounting units, not measured RSS or
// compiled-program execution costs. Classification admits execution separately.
type InterfaceRolePolicyBudget struct{ MemoryBytes, WorkUnits int64 }

func (b *InterfaceRolePolicyBudget) charge(ctx context.Context, count int, bytesEach, workEach int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n := int64(count)
	if n < 0 || bytesEach < 0 || workEach < 0 || b.MemoryBytes < 0 || b.WorkUnits < 0 ||
		(bytesEach > 0 && n > b.MemoryBytes/bytesEach) || (workEach > 0 && n > b.WorkUnits/workEach) {
		return ErrInterfaceRoleBudget
	}
	b.MemoryBytes -= n * bytesEach
	b.WorkUnits -= n * workEach
	return nil
}

// NormalizeInterfaceRolePolicy owns the complete definition or returns none.
// ASN declarations are sets; rule order remains meaningful. Conflicting
// provider/customer declarations, duplicate IDs and invalid syntax fail closed.
func NormalizeInterfaceRolePolicy(ctx context.Context, input InterfaceRolePolicyDefinition, budget InterfaceRolePolicyBudget) (InterfaceRolePolicyDefinition, error) {
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return InterfaceRolePolicyDefinition{}, ErrInterfaceRoleBudget
	}
	if err := budget.charge(ctx, 1, 1024, 1); err != nil {
		return InterfaceRolePolicyDefinition{}, err
	}
	out := InterfaceRolePolicyDefinition{ProviderASNs: []uint32{}, CustomerASNs: []uint32{}, DescriptionRules: []InterfaceRoleDescriptionRule{}}
	declared := map[uint32]InterfaceRole{}
	for _, group := range []struct {
		values []uint32
		role   InterfaceRole
		out    *[]uint32
	}{{input.ProviderASNs, InterfaceRoleTransit, &out.ProviderASNs}, {input.CustomerASNs, InterfaceRoleCustomer, &out.CustomerASNs}} {
		for _, asn := range group.values {
			if err := budget.charge(ctx, 1, 64, 1); err != nil {
				return InterfaceRolePolicyDefinition{}, err
			}
			if asn == 0 || (declared[asn] != "" && declared[asn] != group.role) {
				return InterfaceRolePolicyDefinition{}, ErrInterfaceRolePolicy
			}
			if declared[asn] == "" {
				declared[asn] = group.role
				*group.out = append(*group.out, asn)
			}
		}
		slices.Sort(*group.out)
	}
	ids := map[string]bool{}
	for _, rule := range input.DescriptionRules {
		if err := budget.charge(ctx, 1, 2048, 1); err != nil {
			return InterfaceRolePolicyDefinition{}, err
		}
		if err := budget.charge(ctx, len(rule.Pattern), 128, 1); err != nil {
			return InterfaceRolePolicyDefinition{}, err
		}
		id, err := uuid.Parse(rule.ID)
		if err != nil || id == uuid.Nil || id.String() != rule.ID || ids[rule.ID] ||
			!ValidInterfaceRole(rule.Role) || rule.Pattern == "" || !utf8.ValidString(rule.Pattern) {
			return InterfaceRolePolicyDefinition{}, ErrInterfaceRolePolicy
		}
		// Parse without expanding repeat nodes or compiling an executable
		// program. Evaluation must charge its own current request budget.
		if _, err := syntax.Parse(rule.Pattern, syntax.Perl); err != nil {
			return InterfaceRolePolicyDefinition{}, ErrInterfaceRolePolicy
		}
		ids[rule.ID] = true
		rule.ID, rule.Pattern = strings.Clone(rule.ID), strings.Clone(rule.Pattern)
		out.DescriptionRules = append(out.DescriptionRules, rule)
	}
	return out, nil
}
