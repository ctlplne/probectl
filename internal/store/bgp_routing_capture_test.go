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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const routingCaptureTenant = "11111111-1111-4111-8111-111111111111"

func routingCaptureFixture(t testing.TB) BGPRoutingFlowLookup {
	t.Helper()
	at := time.Date(2026, 11, 1, 12, 0, 0, 123456789, time.UTC)
	scope := entity.Scope{TenantID: routingCaptureTenant, ContextID: "22222222-2222-4222-8222-222222222222"}
	router := "33333333-3333-4333-8333-333333333333"
	path := routingChangeFixture()
	fields, err := routingFlowPathFields(t.Context(), []BGPRoutingChange{path}, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	asn := uint32(65010)
	side := BGPRoutingFlowSide{State: "router_selected", Route: BGPRoutingLookup{
		Source: BGPRoutingSource{Scope: scope, RouterID: router, CollectorAgentID: "collector", SourceRef: "router", SenderSerial: "sender", OriginSerial: "origin", ObservedAt: at.Add(-time.Minute)},
		View:   BGPRoutingViewRef{ID: "55555555-5555-4555-8555-555555555555", Generation: "66666666-6666-4666-8666-666666666666"},
		Prefix: path.Prefix, Paths: []BGPRoutingChange{path}, AsOf: at.Add(-time.Second), ValidUntil: at.Add(time.Minute), LastObservedAt: at.Add(-2 * time.Second), LastSequence: 12,
	}, Fields: fields, NextHops: []BGPRoutingNextHopAS{{ASN: &asn, Sources: []string{"evidence/77777777-7777-4777-8777-777777777777"}, Reason: "current_neighbor_observation", ValidUntil: at.Add(time.Minute)}}}
	return BGPRoutingFlowLookup{Owner: InterfaceRoleFlowBinding{Scope: scope, AgentID: "flow-source", RouterID: router, SourceID: "evidence/44444444-4444-4444-8444-444444444444", Exporter: netip.MustParseAddr("192.0.2.254"), Protocol: "ipfix", Domain: ^uint32(0), InterfaceRoleEvidenceClock: InterfaceRoleEvidenceClock{ObservedAt: at.Add(-time.Minute), ValidUntil: at.Add(time.Hour)}}, CapturedAt: at, Source: side, Destination: side}
}

func TestRoutingCaptureObjectsKeepEveryFieldAndShareContentAcrossClocks(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := routingCaptureFixture(t)
	objects, err := freezeRoutingCapture(ctx, input, routingViewBudget())
	if err != nil {
		t.Fatal("complete capture failed", err)
	}
	got, err := decodeRoutingCapture(ctx, objects, routingViewBudget())
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatal("immutable capture lost complete source, paths, provenance or clocks", got, err)
	}
	if input.Source.Route.LastSequence != 12 || input.Source.NextHops[0].ValidUntil.IsZero() {
		t.Fatal("splitting capture clocks mutated live lookup data")
	}
	later := input
	later.CapturedAt = later.CapturedAt.Add(time.Second)
	later.Source.Route.LastSequence++
	later.Source.Route.LastObservedAt = later.Source.Route.LastObservedAt.Add(time.Second)
	newer, err := freezeRoutingCapture(ctx, later, routingViewBudget())
	if err != nil || newer.facts.digest != objects.facts.digest || newer.clocks.digest == objects.clocks.digest {
		t.Fatal("identical route content did not share immutable facts independently of clocks", err)
	}
	// Changing caller-owned data cannot rewrite an already encoded capture.
	input.Source.Route.Paths[0].Segments[1].Values[0] = 1
	again, err := decodeRoutingCapture(ctx, objects, routingViewBudget())
	if err != nil || again.Source.Route.Paths[0].Segments[1].Values[0] != 4294967295 {
		t.Fatal("caller mutation rewrote frozen routing content", err)
	}
}

func TestRoutingCaptureObjectsKeepExplicitSelectionsAndUnavailableDirections(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := routingCaptureFixture(t)
	selection := &routingSourceSelection{BaseContextID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", BaseRouterID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", ContextID: input.Owner.ContextID, RouterID: input.Owner.RouterID, Epoch: "88888888-8888-4888-8888-888888888888", BindingID: "99999999-9999-4999-8999-999999999999", AssignedAt: input.Source.Route.Source.ObservedAt.Add(-time.Minute), Families: []uint16{1}, Binding: routingSourceBinding{ID: "99999999-9999-4999-8999-999999999999", ContextID: input.Owner.ContextID, RouterID: input.Owner.RouterID, Distinguisher: "1122334455667788", BGPIdentifier: "192.0.2.99", Families: []uint16{1}, SourceFormat: BGPRoutingSourceFRRLocRIBV1}}
	input.Source.Route.Source.routingSelection = selection
	input.Destination = BGPRoutingFlowSide{State: "no_prefix"}
	objects, err := freezeRoutingCapture(ctx, input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRoutingCapture(ctx, objects, routingViewBudget())
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatal("frozen selection lost complete base/target incarnation or invented another direction", got, err)
	}
	for _, state := range []string{"no_prefix", "source_unavailable"} {
		input.Source = BGPRoutingFlowSide{State: state}
		objects, err = freezeRoutingCapture(ctx, input, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		got, err = decodeRoutingCapture(ctx, objects, routingViewBudget())
		if err != nil || got.Source.State != state || got.Source.Route.Paths != nil {
			t.Fatal("unavailable capture invented a path", got, err)
		}
	}
}

func TestRoutingCaptureObjectsRefuseTenantMixCorruptionOldFormatsAndPartialAdmission(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := routingCaptureFixture(t)
	objects, err := freezeRoutingCapture(ctx, input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	for _, wrong := range []context.Context{t.Context(), foreign} {
		if got, err := decodeRoutingCapture(wrong, objects, routingViewBudget()); err == nil || got.Owner.TenantID != "" {
			t.Fatal("routing capture crossed outer tenant scope", err)
		}
		if got, err := freezeRoutingCapture(wrong, input, routingViewBudget()); err == nil || got.facts.payload != "" {
			t.Fatal("foreign input reached capture allocation", err)
		}
	}
	for _, mutate := range []func(*routingCaptureObjects){
		func(o *routingCaptureObjects) { o.facts.payload += " " },
		func(o *routingCaptureObjects) {
			o.facts.payload += " null"
			o.facts.digest = crypto.Hash([]byte(o.facts.payload))
		},
		func(o *routingCaptureObjects) {
			o.facts.payload = strings.TrimSuffix(o.facts.payload, "}") + `,"tenant_id":"` + routingCaptureTenant + `"}`
			o.facts.digest = crypto.Hash([]byte(o.facts.payload))
		},
		func(o *routingCaptureObjects) {
			o.facts.payload = strings.Replace(o.facts.payload, `"version":1`, `"version":2`, 1)
			o.facts.digest = crypto.Hash([]byte(o.facts.payload))
		},
		func(o *routingCaptureObjects) {
			var c routingCaptureClocks
			if err := readRoutingCaptureObject(o.clocks, &c); err != nil {
				t.Fatal(err)
			}
			c.FactsDigest = [32]byte{}
			o.clocks, err = marshalRoutingCaptureObject(c)
			if err != nil {
				t.Fatal(err)
			}
		},
		func(o *routingCaptureObjects) { o.capturedAt = input.Owner.ValidUntil },
	} {
		changed := objects
		mutate(&changed)
		if got, err := decodeRoutingCapture(ctx, changed, routingViewBudget()); err == nil || got.Owner.TenantID != "" || got.Source.Route.Paths != nil {
			t.Fatal("corrupt, mixed or unsupported capture returned partial facts", got, err)
		}
	}
	for _, budget := range []BGPRoutingBudget{{MemoryBytes: 1, WorkUnits: 1, StateBytes: 1}, {MemoryBytes: 8 << 20, WorkUnits: 1, StateBytes: 1}} {
		if got, err := freezeRoutingCapture(ctx, input, budget); !errors.Is(err, ErrBGPRoutingBudget) || got.facts.payload != "" {
			t.Fatal("unadmitted capture encoded partial metadata", err)
		}
		if got, err := decodeRoutingCapture(ctx, objects, budget); !errors.Is(err, ErrBGPRoutingBudget) || got.Owner.TenantID != "" {
			t.Fatal("unadmitted capture decoded partial metadata", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := decodeRoutingCapture(canceled, objects, routingViewBudget()); !errors.Is(err, context.Canceled) || got.Owner.TenantID != "" {
		t.Fatal("cancelled capture exposed data", err)
	}
	if got, err := freezeRoutingCapture(canceled, input, routingViewBudget()); !errors.Is(err, context.Canceled) || got.facts.payload != "" {
		t.Fatal("cancelled capture encoded data", err)
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal([]byte(objects.facts.payload), &header); err != nil {
		t.Fatal(err)
	}
	delete(header, "selections")
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	changed := objects
	changed.facts = routingCaptureObject{payload: string(raw), digest: crypto.Hash(raw)}
	rebindRoutingCaptureClocks(t, &changed)
	if got, err := decodeRoutingCapture(ctx, changed, routingViewBudget()); err == nil || got.Owner.TenantID != "" {
		t.Fatal("omitted capture fields were silently reinterpreted", err)
	}
}

func rebindRoutingCaptureClocks(t testing.TB, objects *routingCaptureObjects) {
	t.Helper()
	var clocks routingCaptureClocks
	if err := readRoutingCaptureObject(objects.clocks, &clocks); err != nil {
		t.Fatal(err)
	}
	clocks.FactsDigest = objects.facts.digest
	var err error
	objects.clocks, err = marshalRoutingCaptureObject(clocks)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRoutingCaptureObjectsRejectRehashedSemanticAndTenantCorruption(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := routingCaptureFixture(t)
	objects, err := freezeRoutingCapture(ctx, input, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*routingCaptureFacts){
		"foreign-owner": func(f *routingCaptureFacts) { f.Data.Owner.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"foreign-route": func(f *routingCaptureFacts) {
			f.Data.Source.Route.Source.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"wrong-context": func(f *routingCaptureFacts) {
			f.Data.Source.Route.Source.ContextID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		"path-text":        func(f *routingCaptureFacts) { f.Data.Source.Fields[0].ASPathText = "65000" },
		"invented-origin":  func(f *routingCaptureFacts) { asn := uint32(65000); f.Data.Source.Fields[0].OriginAS = &asn },
		"missing-path":     func(f *routingCaptureFacts) { f.Data.Source.Route.Paths = nil },
		"next-hop-source":  func(f *routingCaptureFacts) { f.Data.Source.NextHops[0].Sources = []string{"unbound"} },
		"next-hop-unknown": func(f *routingCaptureFacts) { f.Data.Source.NextHops[0].ASN = nil },
		"wrong-state":      func(f *routingCaptureFacts) { f.Data.Source.State = "no_prefix" },
	} {
		t.Run(name, func(t *testing.T) {
			var facts routingCaptureFacts
			if err := readRoutingCaptureObject(objects.facts, &facts); err != nil {
				t.Fatal(err)
			}
			mutate(&facts)
			changed := objects
			changed.facts, err = marshalRoutingCaptureObject(facts)
			if err != nil {
				t.Fatal(err)
			}
			rebindRoutingCaptureClocks(t, &changed)
			if got, err := decodeRoutingCapture(ctx, changed, routingViewBudget()); err == nil || got.Owner.TenantID != "" || got.Source.Route.Paths != nil {
				t.Fatal("rehashed invalid capture exposed facts", err)
			}
		})
	}
}

func TestRoutingCaptureObjectsPreserveCompleteLargePathAndAttributes(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := routingCaptureFixture(t)
	path := &input.Source.Route.Paths[0]
	path.Segments = []BGPRoutingSegment{{Kind: 2, Values: make([]uint32, 65537)}}
	for i := range path.Segments[0].Values {
		path.Segments[0].Values[i] = ^uint32(0) - uint32(i)
	}
	path.Attributes.Wire = append(path.Attributes.Wire, BGPRoutingAttribute{Flags: 0xc0, Type: 99, Value: []byte(strings.Repeat("x", (1<<20)+1))})
	budget := BGPRoutingBudget{MemoryBytes: 512 << 20, WorkUnits: 512 << 20, StateBytes: 512 << 20}
	var err error
	input.Source.Fields, err = routingFlowPathFields(ctx, input.Source.Route.Paths, budget)
	if err != nil {
		t.Fatal(err)
	}
	input.Destination = input.Source
	objects, err := freezeRoutingCapture(ctx, input, budget)
	if err != nil {
		t.Fatal("complete large capture was refused", err)
	}
	got, err := decodeRoutingCapture(ctx, objects, budget)
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatal("complete large capture was truncated or changed", err)
	}
}

func FuzzRoutingCaptureObjects(f *testing.F) {
	ctx := tenancy.WithTenant(f.Context(), tenancy.ID(routingCaptureTenant))
	input := routingCaptureFixture(f)
	objects, err := freezeRoutingCapture(ctx, input, routingViewBudget())
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(objects.facts.payload), []byte(objects.clocks.payload))
	f.Add([]byte(`{"version":1}`), []byte(`null`))
	f.Fuzz(func(t *testing.T, facts, clocks []byte) {
		// This bounds the fuzz harness, not the product's admitted object size.
		if len(facts)+len(clocks) > 2<<20 {
			return
		}
		changed := routingCaptureObjects{facts: routingCaptureObject{payload: string(facts), digest: crypto.Hash(facts)}, clocks: routingCaptureObject{payload: string(clocks), digest: crypto.Hash(clocks)}, capturedAt: input.CapturedAt}
		got, err := decodeRoutingCapture(ctx, changed, routingViewBudget())
		if err != nil {
			if !reflect.DeepEqual(got, BGPRoutingFlowLookup{}) {
				t.Fatal("malformed capture returned partial tenant data", err)
			}
			return
		}
		if got.Owner.TenantID != routingCaptureTenant {
			t.Fatal("capture crossed the outer tenant boundary")
		}
	})
}
