// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func TestRoutingSelectionReaderRefusesUnknownBorrowedAndIncompleteBindings(t *testing.T) {
	ids := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"}
	prepared, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{{ContextID: ids[0], RouterID: ids[1], Distinguisher: "000000000000abcd", BGPIdentifier: "0.0.0.0", Families: []uint16{1, 2}}}, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	source := BGPRoutingSource{Scope: entity.Scope{TenantID: ids[2], ContextID: ids[0]}, RouterID: ids[1], ObservedAt: time.Now().UTC()}
	selected := routingSourceSelection{BaseContextID: ids[2], BaseRouterID: ids[3], ContextID: ids[0], RouterID: ids[1],
		Epoch: ids[3], BindingID: prepared[0].ID, AssignedAt: source.ObservedAt.Add(-time.Second), Families: []uint16{1, 2}, Binding: prepared[0]}
	raw, err := json.Marshal(selected)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRoutingSelection(t.Context(), raw, source, routingViewBudget())
	if err != nil || got == nil || !sameRoutingSelection(*got, selected) {
		t.Fatal("complete routing selection lost canonical target identity", err)
	}
	var unknown map[string]any
	if err := json.Unmarshal(raw, &unknown); err != nil {
		t.Fatal(err)
	}
	unknown["source_format"] = "future-unknown"
	future, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeRoutingSelection(t.Context(), future, source, routingViewBudget()); err == nil || got != nil {
		t.Fatal("stored routing selection accepted unknown authority metadata")
	}
	for _, raw := range [][]byte{nil, []byte("null"), []byte("[]"), append(append([]byte(nil), raw...), []byte(" {}")...)} {
		if got, err := decodeRoutingSelection(t.Context(), raw, source, routingViewBudget()); err == nil || got != nil {
			t.Fatal("partial or ambiguous stored routing selection exposed authority")
		}
	}
	for _, change := range []func(*routingSourceSelection){
		func(s *routingSourceSelection) { s.ContextID = ids[3] },
		func(s *routingSourceSelection) { s.Binding.RouterID = ids[3] },
		func(s *routingSourceSelection) { s.AssignedAt = source.ObservedAt.Add(time.Second) },
		func(s *routingSourceSelection) { s.Families = []uint16{1, 1} },
		func(s *routingSourceSelection) { s.Binding.Families = []uint16{1}; s.Families = []uint16{2} },
	} {
		candidate := selected
		change(&candidate)
		body, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeRoutingSelection(t.Context(), body, source, routingViewBudget()); err == nil || got != nil {
			t.Fatal("borrowed target, old observation or unbound family exposed authority")
		}
	}
	budget := routingViewBudget()
	budget.MemoryBytes = 1
	if got, err := decodeRoutingSelection(t.Context(), raw, source, budget); err == nil || got != nil {
		t.Fatal("unadmitted routing selection exposed partial authority")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if got, err := decodeRoutingSelection(canceled, raw, source, routingViewBudget()); err == nil || got != nil {
		t.Fatal("canceled routing selection exposed authority")
	}
}
