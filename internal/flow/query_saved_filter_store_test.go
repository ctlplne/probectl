// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
)

func TestQueryD102SavedStoreTenantIsolationVersionsAndCopies(t *testing.T) {
	store := NewMemoryQueryFilterStore(1 << 20)
	input := SaveQueryFilter{Name: "TLS ports", Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}}}}
	red, err := store.SaveQueryFilter(t.Context(), "red", "operator", input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetQueryFilter(t.Context(), "blue", red.ID); !errors.Is(err, ErrQueryFilterNotFound) {
		t.Fatalf("foreign saved filter lookup: %v", err)
	}
	if err := store.DeleteQueryFilter(t.Context(), "blue", "operator", red.ID, red.Version); !errors.Is(err, ErrQueryFilterNotFound) {
		t.Fatalf("foreign delete: %v", err)
	}
	red.Expression.Conditions[0].Values[0] = "80"
	stored, err := store.GetQueryFilter(t.Context(), "red", red.ID)
	if err != nil || stored.Expression.Conditions[0].Values[0] != "443" {
		t.Fatalf("returned copy mutated stored expression: %+v %v", stored, err)
	}
	input.ID = red.ID
	input.Version = red.Version
	input.Name = "Updated"
	updated, err := store.SaveQueryFilter(t.Context(), "red", "operator", input)
	if err != nil || updated.Version != red.Version+1 {
		t.Fatalf("update version: %+v %v", updated, err)
	}
	if _, err := store.SaveQueryFilter(t.Context(), "red", "operator", input); !errors.Is(err, ErrQueryFilterConflict) {
		t.Fatalf("stale update accepted: %v", err)
	}
	if err := store.DeleteQueryFilter(t.Context(), "red", "operator", red.ID, red.Version); !errors.Is(err, ErrQueryFilterConflict) {
		t.Fatalf("stale delete accepted: %v", err)
	}
	page, err := store.ListQueryFilters(t.Context(), "blue", "", 10)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("list crossed partition: %+v %v", page, err)
	}
}

func TestQueryD102SavedStoreRefusesUpdateCyclesAndPartialBudgetWrites(t *testing.T) {
	store := NewMemoryQueryFilterStore(1 << 20)
	a, err := store.SaveQueryFilter(t.Context(), "red", "op", SaveQueryFilter{Name: "A", Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "src_addr", Op: QueryCIDR, Values: []string{"192.0.2.0/24"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.SaveQueryFilter(t.Context(), "red", "op", SaveQueryFilter{Name: "B", Expression: QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: a.ID}}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveQueryFilter(t.Context(), "red", "op", SaveQueryFilter{ID: a.ID, Version: a.Version, Name: "cycle", Expression: QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: b.ID}}}}); err == nil {
		t.Fatal("update introduced a cycle")
	}
	still, err := store.GetQueryFilter(t.Context(), "red", a.ID)
	if err != nil || still.Version != 1 || still.Name != "A" {
		t.Fatalf("failed mutation partially wrote: %+v %v", still, err)
	}
	tiny := NewMemoryQueryFilterStore(1)
	if _, err := tiny.SaveQueryFilter(t.Context(), "red", "op", SaveQueryFilter{Name: "A", Expression: a.Expression}); !errors.Is(err, ErrQueryFilterStorageBudget) {
		t.Fatalf("byte budget ignored: %v", err)
	}
	page, err := tiny.ListQueryFilters(t.Context(), "red", "", 10)
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("refused quota write persisted: %+v %v", page, err)
	}
}

func TestQueryD102SavedListBytesAndVersionOverflow(t *testing.T) {
	item := SavedQueryFilter{ID: "first", Name: "one", Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}}}}
	body, _ := json.Marshal(item)
	page := QueryFilterPage{Items: []SavedQueryFilter{}}
	used := 0
	if more, err := appendQueryFilterPage(&page, item, 1000, len(body)+1, &used); err != nil || more {
		t.Fatalf("first: %v %v", more, err)
	}
	item.ID = "second"
	if more, err := appendQueryFilterPage(&page, item, 1000, len(body)+1, &used); err != nil || !more || page.Next != "first" || len(page.Items) != 1 {
		t.Fatalf("byte page: %+v %v %v", page, more, err)
	}
	store := NewMemoryQueryFilterStore(1 << 20)
	item.TenantID = "red"
	item.Version = math.MaxInt64
	store.byTenant["red"] = map[string]SavedQueryFilter{item.ID: item}
	if _, err := store.SaveQueryFilter(t.Context(), "red", "op", SaveQueryFilter{ID: item.ID, Version: item.Version, Name: "updated", Expression: item.Expression}); !errors.Is(err, ErrQueryFilterConflict) {
		t.Fatalf("overflow accepted: %v", err)
	}
}

func TestQueryD102SavedPostgresUnavailableFailsClosed(t *testing.T) {
	store := NewPostgresQueryFilterStore(nil, 0, audit.TenantRecord)
	if _, err := store.GetQueryFilter(t.Context(), "red", "missing"); err == nil {
		t.Fatal("unavailable read accepted")
	}
	if _, err := store.ListQueryFilters(t.Context(), "red", "", 10); err == nil {
		t.Fatal("unavailable list accepted")
	}
	if err := store.DeleteQueryFilter(t.Context(), "red", "operator", "missing", 1); err == nil {
		t.Fatal("unavailable delete accepted")
	}
}

func TestSavedFilterExactRevisionTextAboveJavaScriptLimit(t *testing.T) {
	store := NewMemoryQueryFilterStore(0)
	item, err := store.SaveQueryFilter(t.Context(), "red", "qa", SaveQueryFilter{Name: "exact", Expression: QueryFilterGroup{Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	stored := store.byTenant["red"][item.ID]
	stored.Version = 9007199254740993
	store.byTenant["red"][item.ID] = stored
	got, err := store.GetQueryFilter(t.Context(), "red", item.ID)
	if err != nil || got.VersionText != "9007199254740993" {
		t.Fatal("exact read token lost", err)
	}
	updated, err := store.SaveQueryFilter(t.Context(), "red", "qa", SaveQueryFilter{ID: item.ID, Version: got.Version, Name: got.Name, Expression: got.Expression})
	if err != nil || updated.VersionText != "9007199254740994" {
		t.Fatal("exact write token lost", err)
	}
}
