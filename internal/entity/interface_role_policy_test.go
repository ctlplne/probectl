// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestInterfaceRolePolicyCompleteReachKeepsOrderAndOwnedCopies(t *testing.T) {
	input := InterfaceRolePolicyDefinition{CustomerASNs: []uint32{4200000001}}
	for i := uint32(1); i <= 70001; i++ {
		input.ProviderASNs = append(input.ProviderASNs, 64500+i)
	}
	for i := 0; i < 12001; i++ {
		input.DescriptionRules = append(input.DescriptionRules, InterfaceRoleDescriptionRule{
			ID:      fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1),
			Pattern: "^" + strings.Repeat("uplink-", 10) + fmt.Sprint(i) + "$", Role: InterfaceRoleBackbone})
	}
	budget := InterfaceRolePolicyBudget{MemoryBytes: 256 << 20, WorkUnits: 4 << 20}
	out, err := NormalizeInterfaceRolePolicy(t.Context(), input, budget)
	if err != nil || len(out.ProviderASNs) != 70001 || len(out.DescriptionRules) != 12001 {
		t.Fatal("complete role policy was refused or truncated", err)
	}
	body, err := json.Marshal(out)
	if err != nil || len(body) <= 1<<20 {
		t.Fatal("complete role definition did not exceed the provisional document ceiling", len(body), err)
	}
	for i, rule := range out.DescriptionRules {
		if rule != input.DescriptionRules[i] {
			t.Fatal("explicit description-rule order or content changed", i)
		}
	}
	input.ProviderASNs[0] = 1
	input.DescriptionRules[0].Pattern = "response mutation"
	if out.ProviderASNs[0] != 64501 || out.DescriptionRules[0].Pattern == "response mutation" {
		t.Fatal("caller mutated owned role configuration")
	}
	for _, limit := range []InterfaceRolePolicyBudget{{MemoryBytes: 1024, WorkUnits: budget.WorkUnits}, {MemoryBytes: budget.MemoryBytes, WorkUnits: 1}} {
		if partial, err := NormalizeInterfaceRolePolicy(t.Context(), input, limit); !errors.Is(err, ErrInterfaceRoleBudget) || !reflect.DeepEqual(partial, InterfaceRolePolicyDefinition{}) {
			t.Fatal("role admission returned partial configuration", err)
		}
	}
}

func TestInterfaceRolePolicyRefusesAmbiguityAndKeepsCanonicalSets(t *testing.T) {
	budget := InterfaceRolePolicyBudget{MemoryBytes: 4 << 20, WorkUnits: 1 << 20}
	rule := InterfaceRoleDescriptionRule{ID: "11111111-1111-4111-8111-111111111111", Pattern: "(?m)^customer-[[:digit:]]+$", Role: InterfaceRoleCustomer}
	out, err := NormalizeInterfaceRolePolicy(t.Context(), InterfaceRolePolicyDefinition{ProviderASNs: []uint32{4294967295, 64500, 64500}, CustomerASNs: []uint32{64501}, DescriptionRules: []InterfaceRoleDescriptionRule{rule}}, budget)
	if err != nil || !reflect.DeepEqual(out.ProviderASNs, []uint32{64500, 4294967295}) || out.DescriptionRules[0] != rule {
		t.Fatal("role declarations lost their complete positive ASN domain or canonical set", err)
	}
	for _, bad := range []InterfaceRolePolicyDefinition{
		{ProviderASNs: []uint32{0}}, {ProviderASNs: []uint32{64500}, CustomerASNs: []uint32{64500}},
		{DescriptionRules: []InterfaceRoleDescriptionRule{rule, rule}},
		{DescriptionRules: []InterfaceRoleDescriptionRule{{ID: rule.ID, Pattern: "[", Role: rule.Role}}},
		{DescriptionRules: []InterfaceRoleDescriptionRule{{ID: rule.ID, Pattern: "ok", Role: "unknown"}}},
		{DescriptionRules: []InterfaceRoleDescriptionRule{{ID: rule.ID, Pattern: string([]byte{0xff}), Role: rule.Role}}},
		{DescriptionRules: []InterfaceRoleDescriptionRule{{ID: "00000000-0000-0000-0000-000000000000", Pattern: "ok", Role: rule.Role}}},
	} {
		if partial, err := NormalizeInterfaceRolePolicy(t.Context(), bad, budget); !errors.Is(err, ErrInterfaceRolePolicy) || !reflect.DeepEqual(partial, InterfaceRolePolicyDefinition{}) {
			t.Fatal("ambiguous or invalid rule definition became usable", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NormalizeInterfaceRolePolicy(ctx, InterfaceRolePolicyDefinition{}, budget); !errors.Is(err, context.Canceled) {
		t.Fatal("role policy ignored cancellation", err)
	}
}
