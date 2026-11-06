// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRoutingBindingReaderRefusesUnknownCorruptAndForeignMetadata(t *testing.T) {
	binding := routingSourceBinding{ContextID: "11111111-1111-4111-8111-111111111111", RouterID: "22222222-2222-4222-8222-222222222222", Distinguisher: "0000000000000000", BGPIdentifier: "0.0.0.0", Families: []uint16{1, 2}}
	prepared, err := prepareRoutingBindings(t.Context(), []routingSourceBinding{binding}, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeRoutingBindings(t.Context(), raw, routingViewBudget()); err != nil || len(decoded) != 1 || decoded[0].ID != prepared[0].ID {
		t.Fatal("current canonical routing metadata lost selector identity", err)
	}
	var maps []map[string]any
	if err := json.Unmarshal(raw, &maps); err != nil {
		t.Fatal(err)
	}
	maps[0]["source_format"] = "future-unknown"
	unknown, err := json.Marshal(maps)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		[]byte("null"), []byte("[] {}"),
		unknown,
		append(append(append([]byte(nil), raw[:len(raw)-1]...), ','), raw[1:]...),
	} {
		if decoded, err := decodeRoutingBindings(t.Context(), bad, routingViewBudget()); err == nil || decoded != nil {
			t.Fatal("old routing reader accepted unknown or ambiguous stored metadata")
		}
	}
	prepared[0].Families = []uint16{2, 1}
	bad, err := json.Marshal(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := decodeRoutingBindings(t.Context(), bad, routingViewBudget()); err == nil || decoded != nil {
		t.Fatal("stored routing metadata was silently reinterpreted")
	}
	ctx := tenancy.WithTenant(t.Context(), "red")
	scope := tenancy.Scope{Tenant: "red"}
	if _, err := loadRoutingSourceConfiguration(ctx, tenancy.Scope{Tenant: "blue"}, "", "", routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("foreign selector configuration reached storage")
	}
	config := routingSourceConfiguration{TenantID: "red", BaseContextID: binding.ContextID, BaseRouterID: binding.RouterID}
	peer := BGPRoutingPeer{Type: 3, BGPIdentifier: netip.MustParseAddr("0.0.0.0")}
	if selected, err := selectRoutingSource(ctx, scope, config, peer, []uint16{1, 2}); err != nil || selected.ContextID != binding.ContextID || selected.Epoch != "" {
		t.Fatal("legacy global source acquired an implicit explicit binding", err)
	}
	for _, mutate := range []func(*routingSourceConfiguration, *BGPRoutingPeer){
		func(c *routingSourceConfiguration, _ *BGPRoutingPeer) { c.TenantID = "blue" },
		func(_ *routingSourceConfiguration, p *BGPRoutingPeer) { p.Distinguisher[0] = 1 },
		func(c *routingSourceConfiguration, _ *BGPRoutingPeer) {
			c.Manifest = &routingSourceManifest{Bindings: []routingSourceBinding{}}
		},
	} {
		candidate, header := config, peer
		mutate(&candidate, &header)
		if selected, err := selectRoutingSource(ctx, scope, candidate, header, []uint16{1}); err == nil || selected.ContextID != "" {
			t.Fatal("foreign, withdrawn or unbound selector acquired routing context")
		}
	}
	for _, families := range [][]uint16{nil, {1, 1}, {3}, {1, 2, 1}} {
		if selected, err := selectRoutingSource(ctx, scope, config, peer, families); err == nil || selected.ContextID != "" {
			t.Fatal("unbound family acquired a canonical routing context")
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if selected, err := selectRoutingSource(canceled, scope, config, peer, []uint16{1}); err == nil || selected.ContextID != "" {
		t.Fatal("canceled selector retained context authority")
	}
}
