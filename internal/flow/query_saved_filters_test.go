// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
)

type savedFilterFixture map[string]map[string]SavedQueryFilter

func (s savedFilterFixture) GetQueryFilter(_ context.Context, tenant, id string) (SavedQueryFilter, error) {
	filter, ok := s[tenant][id]
	if !ok {
		return SavedQueryFilter{}, errors.New("saved filter not found")
	}
	return filter, nil
}

func TestQueryD102SavedReferencesExpandInTenantScope(t *testing.T) {
	sameID := "same-filter-id"
	filters := savedFilterFixture{"red": {sameID: {ID: sameID, TenantID: "red", Name: "own", Version: 2, Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}}}}}, "blue": {sameID: {ID: sameID, TenantID: "blue", Name: "foreign", Version: 3, Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "src_as_name", Op: QueryEqual, Values: []string{"secret-blue"}}}}}}}
	root := &QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: sameID, Mode: "exclude"}}}
	result, err := ResolveQueryFilters(t.Context(), "red", root, filters, "")
	if err != nil || result.Versions[sameID] != 2 {
		t.Fatalf("saved resolution=%+v %v", result, err)
	}
	prepared, err := PrepareQueryFilter(result.Expression)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.Matches(func(string) string { return "443" }) {
		t.Fatal("excluded saved expression included its matches")
	}
	if !prepared.Matches(func(string) string { return "80" }) {
		t.Fatal("excluded saved expression discarded nonmatches")
	}
	if result.Expression.Groups[0].Conditions[0].Field != "dst_port" {
		t.Fatal("same saved ID loaded another tenant's expression")
	}
	// A misrouted backend response is rejected rather than postfiltered.
	filters["red"][sameID] = filters["blue"][sameID]
	if _, err := ResolveQueryFilters(t.Context(), "red", root, filters, ""); err == nil {
		t.Fatal("foreign stored expression accepted")
	}
}

func TestQueryD102SavedReferencesRefuseCyclesAndExpandedBudgets(t *testing.T) {
	filters := savedFilterFixture{"red": {}}
	filters["red"]["a"] = SavedQueryFilter{ID: "a", TenantID: "red", Version: 1, Expression: QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "b"}}}}
	filters["red"]["b"] = SavedQueryFilter{ID: "b", TenantID: "red", Version: 1, Expression: QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "a"}}}}
	root := &QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "a"}}}
	if _, err := ResolveQueryFilters(t.Context(), "red", root, filters, ""); err == nil {
		t.Fatal("reference cycle accepted")
	}
	if _, err := ResolveQueryFilters(t.Context(), "red", root, filters, "a"); err == nil {
		t.Fatal("update introduced a self-reference cycle")
	}
	conditions := make([]QueryPredicate, 250)
	for i := range conditions {
		conditions[i] = QueryPredicate{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}
	}
	filters["red"]["wide"] = SavedQueryFilter{ID: "wide", TenantID: "red", Version: 1, Expression: QueryFilterGroup{Conditions: conditions}}
	root = &QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "wide"}, {ID: "wide"}, {ID: "wide"}, {ID: "wide"}}}
	if _, err := ResolveQueryFilters(t.Context(), "red", root, filters, ""); err != nil {
		t.Fatalf("1000 expanded conditions rejected: %v", err)
	}
	root.Saved = append(root.Saved, QuerySavedFilterRef{ID: "wide"})
	if _, err := ResolveQueryFilters(t.Context(), "red", root, filters, ""); err == nil {
		t.Fatal("expanded1250 conditions passed the1000 guard")
	}
}

func TestTagSavedFilterResolutionKeepsTenantVocabulary(t *testing.T) {
	red, blue := uuid.NewString(), uuid.NewString()
	vocabulary, err := NewTagQueryVocabulary(red, []tags.Definition{
		{TenantID: red, ID: uuid.NewString(), Key: "customer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	filters := savedFilterFixture{red: {"saved": {ID: "saved", TenantID: red, Version: 1,
		Expression: QueryFilterGroup{Conditions: []QueryPredicate{
			{Field: "tag.customer", Op: QueryEqual, Values: []string{"blue"}},
		}}}}}
	root := &QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "saved"}}}
	if _, err := ResolveQueryFilters(t.Context(), red, root, filters, ""); err == nil {
		t.Fatal("native-only saved resolution accepted tenant tag")
	}
	resolved, err := ResolveQueryFiltersWithVocabulary(t.Context(), red, root, filters, "", vocabulary)
	if err != nil || resolved.Expression.Groups[0].Conditions[0].Field != "tag.customer" {
		t.Fatalf("tag predicate lost during saved expansion: %+v, %v", resolved, err)
	}
	if _, err := ResolveQueryFiltersWithVocabulary(t.Context(), blue, root, filters, "", vocabulary); err == nil {
		t.Fatal("foreign tenant reused tag vocabulary")
	}
	filters[red]["saved"] = SavedQueryFilter{ID: "saved", TenantID: blue, Version: 1,
		Expression: filters[red]["saved"].Expression}
	if _, err := ResolveQueryFiltersWithVocabulary(t.Context(), red, root, filters, "", vocabulary); err == nil {
		t.Fatal("foreign saved filter accepted")
	}
}

func TestSavedTagFilterStoreRevalidatesTenantVocabulary(t *testing.T) {
	tenant, foreign := uuid.NewString(), uuid.NewString()
	vocabulary, err := NewTagQueryVocabulary(tenant, []tags.Definition{
		{TenantID: tenant, ID: uuid.NewString(), Key: "customer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := WithQueryVocabulary(t.Context(), tenant, vocabulary)
	if err != nil {
		t.Fatal(err)
	}
	store := NewMemoryQueryFilterStore(0)
	input := SaveQueryFilter{Name: "customer", Expression: QueryFilterGroup{Conditions: []QueryPredicate{
		{Field: "tag.customer", Op: QueryEqual, Values: []string{"blue"}},
	}}}
	if _, err := store.SaveQueryFilter(t.Context(), tenant, "actor", input); err == nil {
		t.Fatal("native-only store accepted a tenant tag")
	}
	saved, err := store.SaveQueryFilter(ctx, tenant, "actor", input)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.GetQueryFilter(ctx, tenant, saved.ID)
	if err != nil || got.Expression.Conditions[0].Field != "tag.customer" {
		t.Fatalf("saved tag filter lost tenant field: %+v, %v", got, err)
	}
	if _, err := store.GetQueryFilter(t.Context(), tenant, saved.ID); err == nil {
		t.Fatal("stored tag expression escaped its request-local vocabulary")
	}
	if _, err := store.GetQueryFilter(ctx, foreign, saved.ID); err == nil {
		t.Fatal("foreign tenant read saved tag filter")
	}
	if _, err := WithQueryVocabulary(t.Context(), foreign, vocabulary); err == nil {
		t.Fatal("foreign tenant bound another tenant's vocabulary")
	}
}
