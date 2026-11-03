// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestTestTagFilterRejectsUnownedNegativeMatchesAndStaleBindings(t *testing.T) {
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const foreign = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const tagID = "11111111-1111-4111-8111-111111111111"
	const testID = "22222222-2222-4222-8222-222222222222"
	const emptyID = "33333333-3333-4333-8333-333333333333"
	const unknown = "44444444-4444-4444-8444-444444444444"
	const contextID = "55555555-5555-4555-8555-555555555555"
	owned := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	clock := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	wide := strings.Repeat("🌐", tags.MaxValueCharacters)
	snapshot := &TestTagSnapshot{tenantID: tenant, revision: 9007199254740993, asOf: clock,
		definitions: []tags.Definition{{TenantID: tenant, ID: tagID, Key: "customer"}},
		subjects:    map[string]ResolvedTagSubject{},
	}
	for _, id := range []string{testID, emptyID} {
		item := ResolvedTagSubject{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, Kind: "test", ID: id, Revision: snapshot.revision, AsOf: clock}
		if id == testID {
			item.Items = []tags.Resolved{{TagID: tagID, Key: "customer", Value: wide, Source: "rule", Revision: snapshot.revision}}
		}
		snapshot.subjects[id] = item
	}
	allowed := map[string]bool{contextID: true}
	input := &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{wide}}}}
	filter, binding, err := snapshot.BindFilter(owned, tenant, input, 4<<20)
	if err != nil || binding["tag.customer"] != tagID {
		t.Fatal("complete Unicode predicate did not bind its immutable definition")
	}
	ids := []string{testID, testID, emptyID, unknown, "same-target", "https://same.example"}
	selected, err := snapshot.SelectContext(owned, tenant, ids, allowed, filter, binding, 4<<20)
	if err != nil || !reflect.DeepEqual(selected, []string{testID}) {
		t.Fatalf("exact wide value selection = %v, %v", selected, err)
	}
	selected[0] = "mutated-copy"
	again, err := snapshot.SelectContext(owned, tenant, ids, allowed, filter, binding, 4<<20)
	if err != nil || !reflect.DeepEqual(again, []string{testID}) {
		t.Fatal("selected identity slice mutated the snapshot")
	}
	negative := &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryNotEqual, Values: []string{wide}}}}
	negative, negativeIDs, err := snapshot.BindFilter(owned, tenant, negative, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	selected, err = snapshot.SelectContext(owned, tenant, ids, allowed, negative, negativeIDs, 4<<20)
	if err != nil || !reflect.DeepEqual(selected, []string{emptyID}) {
		t.Fatal("negative predicate admitted an unowned/unbound identity or lost a known empty subject")
	}
	for _, policy := range []map[string]bool{{}, {contextID: false}} {
		selected, err := snapshot.SelectContext(owned, tenant, ids, policy, negative, negativeIDs, 4<<20)
		if err != nil || len(selected) != 0 {
			t.Fatal("negative predicate selected a denied current context")
		}
	}
	for _, saved := range []map[string]string{nil, {}, {"tag.customer": unknown}, {"tag.customer": tagID, "tag.extra": tagID}} {
		partial, err := snapshot.SelectContext(owned, tenant, ids, allowed, filter, saved, 4<<20)
		if !errors.Is(err, flow.ErrQueryViewStaleTag) || partial != nil {
			t.Fatal("missing or replaced immutable binding did not refuse atomically")
		}
	}
	for _, scope := range []struct {
		ctx     context.Context
		tenant  string
		allowed map[string]bool
	}{
		{t.Context(), tenant, allowed}, {owned, foreign, allowed}, {tenancy.WithTenant(t.Context(), tenancy.ID(foreign)), foreign, allowed}, {owned, tenant, nil},
	} {
		if partial, err := snapshot.SelectContext(scope.ctx, scope.tenant, ids, scope.allowed, negative, negativeIDs, 4<<20); !errors.Is(err, tags.ErrScopeMismatch) || partial != nil {
			t.Fatal("selection crossed tenant or missing current policy")
		}
	}
	for _, budget := range []int64{0, 1, 80 << 10} {
		if partial, _, err := snapshot.BindFilter(owned, tenant, input, budget); !errors.Is(err, ErrTagSnapshotBudget) || partial != nil {
			t.Fatal("wide predicate escaped its preparation budget")
		}
	}
	// A later cost failure must discard an earlier selected ID too.
	small := &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{""}}}}
	small, smallIDs, err := snapshot.BindFilter(owned, tenant, small, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	many := make([]string, 3000)
	for i := range many {
		many[i] = emptyID
	}
	if partial, err := snapshot.SelectContext(owned, tenant, many, allowed, small, smallIDs, 1<<20); !errors.Is(err, ErrTagSnapshotBudget) || partial != nil {
		t.Fatal("late selection budget failure returned a partial identity set")
	}
	canceled, cancel := context.WithCancel(owned)
	cancel()
	if partial, err := snapshot.SelectContext(canceled, tenant, ids, allowed, filter, binding, 4<<20); !errors.Is(err, context.Canceled) || partial != nil {
		t.Fatal("canceled selection returned partial IDs")
	}
}

func TestTestTagFilterRefusesOtherSubjectsAndUntrustedGrammar(t *testing.T) {
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	owned := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	snapshot := &TestTagSnapshot{tenantID: tenant, revision: 1, asOf: time.Now(), definitions: []tags.Definition{{TenantID: tenant, ID: "11111111-1111-4111-8111-111111111111", Key: "customer"}}}
	for _, field := range []string{"src_addr", "tenant_id", "tag.device.customer", "tag.agent.customer", "tag.src_prefix.customer", "tag.unknown"} {
		input := &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: field, Op: flow.QueryEqual, Values: []string{"x"}}}}
		if filter, _, err := snapshot.BindFilter(owned, tenant, input, 4<<20); err == nil || filter != nil {
			t.Fatalf("non-test tag field %s was accepted", field)
		}
	}
	invalid := []*flow.QueryFilterGroup{nil, {},
		{Saved: []flow.QuerySavedFilterRef{{ID: "flow-reference"}}},
		{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryRegex, Values: []string{"["}}}},
		{Conditions: make([]flow.QueryPredicate, flow.MaxQueryGroupEntries+1)},
	}
	deep := flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: flow.QueryEqual, Values: []string{"x"}}}}
	for i := 0; i < flow.MaxQueryFilterDepth; i++ {
		deep = flow.QueryFilterGroup{Groups: []flow.QueryFilterGroup{deep}}
	}
	invalid = append(invalid, &deep)
	for _, input := range invalid {
		if filter, _, err := snapshot.BindFilter(owned, tenant, input, 4<<20); err == nil || filter != nil {
			t.Fatal("untrusted metadata predicate grammar was accepted")
		}
	}
}
