// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func interfaceRoleEvaluationRecord(facts interfaceRoleFacts) entity.InterfaceRolePolicyRecord {
	return entity.InterfaceRolePolicyRecord{Scope: facts.Scope,
		ID: "44444444-4444-4444-8444-444444444444", Revision: "9007199254740993",
		Definition: entity.InterfaceRolePolicyDefinition{ProviderASNs: []uint32{64496, 4294967295}},
		UpdatedAt:  facts.Clock.ObservedAt}
}

func interfaceRoleEvaluationBudget() interfaceRoleBudget {
	return interfaceRoleBudget{MemoryBytes: 512 << 20, WorkUnits: 1 << 30}
}

// Component fixtures only. The shipping loader must still prove current RLS,
// canonical ownership, producer certificates and real router observations.
func TestInterfaceRoleConfiguredEvaluationKeepsCompleteOrderAndVersionedSources(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		t.Run(tenant, func(t *testing.T) {
			facts, _, at := interfaceRoleFixture(tenant)
			record := interfaceRoleEvaluationRecord(facts)
			for i := range 4095 {
				record.Definition.DescriptionRules = append(record.Definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{
					ID: fmt.Sprintf("%08x-5555-4555-8555-555555555555", i+1), Pattern: fmt.Sprintf("^not-this-interface-%d$", i), Role: interfaceRoleOther})
			}
			winner := entity.InterfaceRoleDescriptionRule{ID: "fffffffe-5555-4555-8555-555555555555", Pattern: `(?i)^transit [\p{L} ]+$`, Role: interfaceRolePrivate}
			later := entity.InterfaceRoleDescriptionRule{ID: "00000000-5555-4555-8555-555555555555", Pattern: "^Transit", Role: interfaceRoleBackbone}
			record.Definition.DescriptionRules = append(record.Definition.DescriptionRules, winner, later)
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			got, err := evaluateInterfaceRoleConfiguration(ctx, facts, record, nil, "Transit é 線", at, nil, interfaceRoleEvaluationBudget())
			expectedSource := "policy/" + record.ID + "/" + record.Revision + "/rule/" + winner.ID
			if err != nil || got.Role != interfaceRolePrivate || got.Reason != "description_rule" || got.Scope != facts.Scope ||
				!slices.Contains(got.Sources, expectedSource) || !slices.Contains(got.Sources, facts.SourceID) {
				t.Fatal("complete ordered role policy lost the earliest match or exact versioned provenance", got, err)
			}
			// A policy edit changes order, not IDs, and must change the selected
			// source/role. Lexical UUID order must never choose the winner.
			record.Definition.DescriptionRules[4095], record.Definition.DescriptionRules[4096] = later, winner
			record.Revision = "9007199254740994"
			got, err = evaluateInterfaceRoleConfiguration(ctx, facts, record, nil, "Transit é 線", at, nil, interfaceRoleEvaluationBudget())
			if err != nil || got.Role != interfaceRoleBackbone || !slices.Contains(got.Sources, "policy/"+record.ID+"/9007199254740994/rule/"+later.ID) {
				t.Fatal("reclassification ignored ordered policy edit", got, err)
			}
			record.Definition.DescriptionRules = nil
			facts.Peers[0].ASN = 4294967295
			got, err = evaluateInterfaceRoleConfiguration(ctx, facts, record, nil, "", at, nil, interfaceRoleEvaluationBudget())
			if err != nil || got.Role != interfaceRoleTransit || !slices.Contains(got.Sources, "policy/"+record.ID+"/"+record.Revision) {
				t.Fatal("complete positive ASN domain lost declaration provenance", got, err)
			}
		})
	}
	// A valid expression longer than the old tag engine's pattern ceiling is
	// still a supported role rule when the operator admits its complete cost.
	facts, _, at := interfaceRoleFixture("11111111-1111-4111-8111-111111111111")
	record := interfaceRoleEvaluationRecord(facts)
	text := strings.Repeat("x", 8193)
	record.Definition.DescriptionRules = []entity.InterfaceRoleDescriptionRule{{ID: "55555555-5555-4555-8555-555555555555", Pattern: "^" + text + "$", Role: interfaceRoleBackbone}}
	got, err := evaluateInterfaceRoleConfiguration(tenancy.WithTenant(t.Context(), tenancy.ID(facts.Scope.TenantID)), facts, record, nil, text, at, nil, interfaceRoleEvaluationBudget())
	if err != nil || got.Role != interfaceRoleBackbone {
		t.Fatal("admitted complete description rule inherited an unrelated pattern ceiling", got, err)
	}
}

func TestInterfaceRoleConfiguredEvaluationRefusesForeignInvalidAndPartialResults(t *testing.T) {
	facts, _, at := interfaceRoleFixture("11111111-1111-4111-8111-111111111111")
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(facts.Scope.TenantID))
	base := interfaceRoleEvaluationRecord(facts)
	rule := entity.InterfaceRoleDescriptionRule{ID: "55555555-5555-4555-8555-555555555555", Pattern: ".*", Role: interfaceRoleBackbone}
	base.Definition.DescriptionRules = []entity.InterfaceRoleDescriptionRule{rule}
	for _, name := range []string{"policy-tenant", "policy-context", "override-tenant", "override-interface", "zero-version-body", "missing-version-id", "rounded-revision", "malformed-after-match", "duplicate-rule", "asn-overlap", "utf8", "no-tenant", "foreign-tenant", "canceled", "budget"} {
		t.Run(name, func(t *testing.T) {
			record := base
			record.Definition.DescriptionRules = slices.Clone(base.Definition.DescriptionRules)
			callCtx, description, budget := ctx, "owned interface", interfaceRoleEvaluationBudget()
			var override *entity.InterfaceRoleOverrideRecord
			switch name {
			case "policy-tenant":
				record.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "policy-context":
				record.ContextID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
			case "override-tenant", "override-interface":
				override = &entity.InterfaceRoleOverrideRecord{Scope: facts.Scope, InterfaceID: facts.InterfaceID,
					ID: "66666666-6666-4666-8666-666666666666", Revision: "1", Role: interfaceRoleCustomer}
				if name == "override-tenant" {
					override.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
				} else {
					override.InterfaceID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
				}
			case "zero-version-body":
				record.ID, record.Revision = "", "0"
			case "missing-version-id":
				record.ID = ""
			case "rounded-revision":
				record.Revision = "9.007199254740993e+15"
			case "malformed-after-match":
				record.Definition.DescriptionRules = append(record.Definition.DescriptionRules, entity.InterfaceRoleDescriptionRule{ID: "77777777-7777-4777-8777-777777777777", Pattern: "[", Role: interfaceRoleCustomer})
			case "duplicate-rule":
				record.Definition.DescriptionRules = append(record.Definition.DescriptionRules, rule)
			case "asn-overlap":
				record.Definition.CustomerASNs = []uint32{64496}
			case "utf8":
				description = string([]byte{255})
			case "no-tenant":
				callCtx = t.Context()
			case "foreign-tenant":
				callCtx = tenancy.WithTenant(t.Context(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
			case "canceled":
				var cancel context.CancelFunc
				callCtx, cancel = context.WithCancel(ctx)
				cancel()
			case "budget":
				budget.WorkUnits = 1
			}
			got, err := evaluateInterfaceRoleConfiguration(callCtx, facts, record, override, description, at, nil, budget)
			if err == nil || !reflect.DeepEqual(got, interfaceRoleDecision{}) {
				t.Fatal("invalid or foreign configured role returned a partial decision", got, err)
			}
		})
	}
}

func TestInterfaceRoleConfiguredEvaluationAdmitsExpansionBeforeCompilation(t *testing.T) {
	facts, _, at := interfaceRoleFixture("11111111-1111-4111-8111-111111111111")
	record := interfaceRoleEvaluationRecord(facts)
	record.Definition.DescriptionRules = []entity.InterfaceRoleDescriptionRule{{ID: "55555555-5555-4555-8555-555555555555", Pattern: strings.Repeat("a{1000}", 128), Role: interfaceRoleBackbone}}
	got, err := evaluateInterfaceRoleConfiguration(tenancy.WithTenant(t.Context(), tenancy.ID(facts.Scope.TenantID)), facts, record, nil, "a", at, nil,
		interfaceRoleBudget{MemoryBytes: 512 << 10, WorkUnits: 1 << 30})
	if !errors.Is(err, errInterfaceRoleBudget) || !reflect.DeepEqual(got, interfaceRoleDecision{}) {
		t.Fatal("expanded role regex compiled without complete resource admission", got, err)
	}
}

func TestInterfaceRoleConfiguredEvaluationKeepsOverrideAcrossWithdrawalAndReset(t *testing.T) {
	facts, _, at := interfaceRoleFixture("11111111-1111-4111-8111-111111111111")
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(facts.Scope.TenantID))
	record := interfaceRoleEvaluationRecord(facts)
	override := &entity.InterfaceRoleOverrideRecord{Scope: facts.Scope, InterfaceID: facts.InterfaceID,
		ID: "66666666-6666-4666-8666-666666666666", Revision: "9007199254740995", Role: interfaceRoleCustomer}
	for _, available := range []bool{true, false} {
		current := facts
		if !available {
			current = interfaceRoleFacts{Scope: facts.Scope, InterfaceID: facts.InterfaceID}
		}
		got, err := evaluateInterfaceRoleConfiguration(ctx, current, record, override, "", at, nil, interfaceRoleEvaluationBudget())
		if err != nil || got.Role != interfaceRoleCustomer || got.Reason != "operator_override" ||
			!slices.Equal(got.Sources, []string{"override/" + override.ID + "/" + override.Revision}) {
			t.Fatal("owned versioned override did not survive source withdrawal", got, err)
		}
		got, err = evaluateInterfaceRoleConfiguration(ctx, current, record, nil, "", at, nil, interfaceRoleEvaluationBudget())
		if err != nil || (available && got.Role != interfaceRoleTransit) || (!available && (got.Role != interfaceRoleOther || got.Reason != "insufficient_evidence")) {
			t.Fatal("override reset did not restore current automatic evidence", got, err)
		}
	}
}
