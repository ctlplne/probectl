// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestQueryLibraryAdmissionKeepsCompletePairedPopulation(t *testing.T) {
	const count = 1500
	filters := NewMemoryQueryFilterStore(0)
	views := NewMemoryQueryViewStore(filters, 0)
	for _, bytes := range []int{1, 1 << 30} {
		if NewMemoryQueryFilterStore(bytes).maxBytesPerTenant != bytes || NewMemoryQueryViewStore(nil, bytes).maxBytes != bytes ||
			NewPostgresQueryFilterStore(nil, bytes, nil).maxBytesPerTenant != bytes || NewPostgresQueryViewStore(nil, bytes, nil).maxBytes != bytes {
			t.Fatal("explicit positive library profile was refused or clamped")
		}
	}
	for lane, tenant := range []string{"red", "blue"} {
		expression := QueryFilterGroup{Match: "any", Mode: "include"}
		for group := 0; group < 4; group++ {
			child := QueryFilterGroup{Match: "any", Mode: "include"}
			for offset := 0; offset < 250; offset++ {
				index := group*250 + offset
				child.Conditions = append(child.Conditions, QueryPredicate{Field: "src_addr", Op: QueryEqual,
					Values: []string{fmt.Sprintf("10.%d.%d.%d", lane+1, index/256, index%256)}})
			}
			expression.Groups = append(expression.Groups, child)
		}
		input, err := NormalizeSaveQueryFilter(SaveQueryFilter{Name: tenant + "-new", Expression: expression})
		if err != nil {
			t.Fatal("complete library workload is not valid native grammar", err)
		}
		wire, err := json.Marshal(input.Expression)
		if err != nil || int64(len(wire))*count <= 64<<20 {
			t.Fatal("complete library did not exercise the former byte quota", err)
		}
		definition := queryViewFixture()
		definition.Name = tenant + "-new"
		definition.Plan.Filter = &input.Expression
		definition, err = NormalizeQueryViewDefinition(definition, time.Now())
		if err != nil {
			t.Fatal("complete saved-query workload is invalid", err)
		}
		// Seed normalized fixture state to avoid quadratic repeated quota scans
		// during setup. The next writes exercise the actual admission boundary;
		// all 1501 records are then read through the native paged services.
		// This is a memory/reference simulation, not a real import/SSO receipt.
		filters.byTenant[tenant] = map[string]SavedQueryFilter{}
		views.byTenant[tenant] = map[string]SavedQueryView{}
		for index := 0; index < count; index++ {
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", index+1)
			name := fmt.Sprintf("%s-%04d", tenant, index)
			filters.byTenant[tenant][id] = SavedQueryFilter{ID: id, TenantID: tenant, Name: name,
				Expression: input.Expression, Version: 1, UpdatedBy: "alice"}
			copy := definition
			copy.Name = name
			views.byTenant[tenant][id] = SavedQueryView{ID: id, TenantID: tenant, OwnerID: "alice", Version: "1", Definition: copy}
		}
		if _, err := filters.SaveQueryFilter(t.Context(), tenant, "alice", input); err != nil {
			t.Fatal("complete saved library retains former fixed byte quota", err)
		}
		if _, err := views.SaveQueryView(t.Context(), tenant, "alice", SaveQueryView{Definition: definition}); err != nil {
			t.Fatal("complete saved library retains former fixed byte quota", err)
		}
		firstValue := fmt.Sprintf("10.%d.0.0", lane+1)
		seenFilters, seenViews := map[string]bool{}, map[string]bool{}
		for after := ""; ; {
			page, err := filters.ListQueryFilters(t.Context(), tenant, after, 32)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				actual, err := json.Marshal(item.Expression)
				if err != nil || string(actual) != string(wire) {
					t.Fatal("complete memory filter expression changed", err)
				}
				if seenFilters[item.ID] || item.TenantID != tenant || !strings.HasPrefix(item.Name, tenant+"-") ||
					item.Expression.Groups[0].Conditions[0].Values[0] != firstValue {
					t.Fatal("complete filter library repeated, changed or crossed a tenant")
				}
				seenFilters[item.ID] = true
			}
			if page.Next == "" {
				break
			}
			after = page.Next
		}
		for after := ""; ; {
			page, err := views.ListQueryViews(t.Context(), tenant, "alice", QueryViewList{After: after, Limit: 32})
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				actual, err := json.Marshal(item.Definition.Plan.Filter)
				if err != nil || string(actual) != string(wire) {
					t.Fatal("complete memory query expression changed", err)
				}
				if seenViews[item.ID] || item.TenantID != tenant || !strings.HasPrefix(item.Definition.Name, tenant+"-") ||
					item.Definition.Plan.Filter.Groups[0].Conditions[0].Values[0] != firstValue {
					t.Fatal("complete saved-query library repeated, changed or crossed a tenant")
				}
				seenViews[item.ID] = true
			}
			if page.Next == "" {
				break
			}
			after = page.Next
		}
		if len(seenFilters) != count+1 || len(seenViews) != count+1 {
			t.Fatal("complete query library was truncated", len(seenFilters), len(seenViews))
		}
		if _, err := views.GetQueryView(t.Context(), tenant, "bob", "00000000-0000-4000-8000-000000000001"); !errors.Is(err, ErrQueryViewNotFound) {
			t.Fatal("private library crossed owner", err)
		}
		if _, err := NewMemoryQueryFilterStore(1).SaveQueryFilter(t.Context(), tenant, "alice", input); !errors.Is(err, ErrQueryFilterStorageBudget) {
			t.Fatal("small positive filter admission stopped refusing", err)
		}
		if _, err := NewMemoryQueryViewStore(nil, 1).SaveQueryView(t.Context(), tenant, "alice", SaveQueryView{Definition: definition}); !errors.Is(err, ErrQueryViewBudget) {
			t.Fatal("small positive saved-query admission stopped refusing", err)
		}
	}
}

func TestQueryLibraryAdmissionArithmeticCannotWrap(t *testing.T) {
	for _, test := range []struct {
		used, additional, budget int64
		fits                     bool
	}{
		{0, 1, 1, true}, {1, 1, 1, false}, {0, 1, 0, false}, {-1, 1, 10, false}, {0, -1, 10, false},
		{math.MaxInt64 - 1, 1, math.MaxInt64, true}, {math.MaxInt64, 1, math.MaxInt64, false},
	} {
		if queryLibraryBytesFit(test.used, test.additional, test.budget) != test.fits {
			t.Fatal("library arithmetic changed whole-operation admission", test)
		}
	}
}
