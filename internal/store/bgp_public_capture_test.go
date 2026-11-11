// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Match the existing authenticated flow capture operation, rather than the
// smaller router-view fixture allowance. Complete binary identity stays intact.
func publicCaptureBudget() BGPRoutingBudget {
	return BGPRoutingBudget{MemoryBytes: 2 << 30, WorkUnits: 2 << 30, StateBytes: 64 << 30}
}

func publicCaptureFixture(t testing.TB) BGPRoutingFlowLookup {
	t.Helper()
	lookup := routingCaptureFixture(t)
	previous := lookup.Source.Route
	peer := *publicRoutingMetadataFixture().Public
	peer.ViewName = bytes.Repeat([]byte{0, 255}, 32767)
	peer.ViewName = append(peer.ViewName, 0)
	clock := previous.Source.ObservedAt.Add(-time.Minute).UnixNano()
	peer.ObservedUnixNanos = &clock
	path := previous.Paths[0]
	path.NextHops = []netip.Addr{peer.PeerAddress.Unmap()}
	original := BGPPublicRoutingLookup{Source: BGPPublicRoutingSource{Scope: lookup.Owner.Scope, CollectorAgentID: "public-collector", SourceRef: publicRoutingSourceRef(peer), SenderSerial: "public-issued", ObservedAt: previous.Source.ObservedAt}, SnapshotID: previous.View.Generation, SourceObservedUnixNanos: clock, Prefix: previous.Prefix, Paths: []BGPPublicRoutingPath{{View: previous.View, Peer: peer, Path: path}}, AsOf: previous.AsOf, ValidUntil: previous.ValidUntil}
	public := BGPPublicContextLookup{Scope: lookup.Owner.Scope, Sources: []BGPPublicRoutingLookup{original}, Prefix: original.Prefix, Paths: append([]BGPPublicRoutingPath(nil), original.Paths...), AsOf: original.AsOf, ValidUntil: original.ValidUntil}
	fields, hops, err := publicRoutingFlowFields(t.Context(), public, publicCaptureBudget())
	if err != nil {
		t.Fatal(err)
	}
	lookup.Source = BGPRoutingFlowSide{State: "public_fallback", Public: &public, RouterState: "source_unavailable", Fields: fields, NextHops: hops}
	return lookup
}

func TestPublicCaptureKeepsWholeOriginalCohortAndSeparatesObservationClocks(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := publicCaptureFixture(t)
	objects, err := freezeRoutingCapture(ctx, input, publicCaptureBudget())
	if err != nil {
		t.Fatal("complete public capture was refused", err)
	}
	if input.Source.Public.AsOf.IsZero() || input.Source.Public.Sources[0].AsOf.IsZero() {
		t.Fatal("public capture clock splitting mutated original source observations")
	}
	got, err := decodeRoutingCapture(ctx, objects, publicCaptureBudget())
	if err != nil || !reflect.DeepEqual(got, input) || !bytes.Contains([]byte(objects.facts.payload), []byte(`"version":2`)) {
		t.Fatal("public capture lost complete original provenance or its version", got, err)
	}
	if input.Source.Public.AsOf.IsZero() || input.Source.Public.Sources[0].AsOf.IsZero() || len(got.Source.Public.Paths[0].Peer.ViewName) != 65535 || got.Source.Public.Paths[0].Peer.PeerBGPIdentifier == nil || *got.Source.Public.Paths[0].Peer.PeerBGPIdentifier != 0 || got.Source.NextHops[0].ASN == nil || *got.Source.NextHops[0].ASN != ^uint32(0) || got.Source.NextHops[0].Reason != "public_peer_observation" {
		t.Fatal("public capture changed original binary identity, full ASN or live clocks")
	}
	later := input
	later.CapturedAt = later.CapturedAt.Add(time.Second)
	public := *input.Source.Public
	public.Sources = append([]BGPPublicRoutingLookup(nil), public.Sources...)
	public.AsOf = public.AsOf.Add(time.Millisecond)
	public.Sources[0].AsOf = public.Sources[0].AsOf.Add(time.Millisecond)
	later.Source.Public = &public
	newer, err := freezeRoutingCapture(ctx, later, publicCaptureBudget())
	if err != nil || newer.facts.digest != objects.facts.digest || newer.clocks.digest == objects.clocks.digest {
		t.Fatal("public capture did not share original facts separately from observation clocks", err)
	}
	input.Source.Public.Paths[0].Peer.ViewName[0] = 99
	again, err := decodeRoutingCapture(ctx, objects, publicCaptureBudget())
	if err != nil || again.Source.Public.Paths[0].Peer.ViewName[0] != 0 {
		t.Fatal("caller mutation rewrote immutable public capture", err)
	}
}

func TestPublicCaptureKeepsCompletePrefixAbsenceAndRefusesPartialForeignOrForgedFacts(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	for _, mutate := range []func(*BGPRoutingFlowLookup){
		func(v *BGPRoutingFlowLookup) { v.Source.Public.Scope.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		func(v *BGPRoutingFlowLookup) {
			v.Source.Public.Sources[0].Source.ContextID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		func(v *BGPRoutingFlowLookup) { v.Source.Public.Paths = nil },
		func(v *BGPRoutingFlowLookup) { v.Source.Public.Sources = nil },
		func(v *BGPRoutingFlowLookup) {
			v.Source.Public.Sources[0].SnapshotID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		},
		func(v *BGPRoutingFlowLookup) { v.Source.Public.Sources[0].ValidUntil = v.CapturedAt },
		func(v *BGPRoutingFlowLookup) {
			v.Source.Public.Paths[0].Path.Prefix = netip.MustParsePrefix("203.0.113.0/24")
		},
		func(v *BGPRoutingFlowLookup) { v.Source.RouterState = "router_selected" },
		func(v *BGPRoutingFlowLookup) { v.Source.Route = v.Destination.Route },
		func(v *BGPRoutingFlowLookup) { v.Source.Fields[0].ASPathText = "64500" },
		func(v *BGPRoutingFlowLookup) { v.Source.NextHops[0].ASN = nil },
	} {
		input := publicCaptureFixture(t)
		mutate(&input)
		if got, err := freezeRoutingCapture(ctx, input, publicCaptureBudget()); err == nil || got.facts.payload != "" {
			t.Fatal("public capture accepted foreign, partial or forged original provenance", err)
		}
	}
	input := publicCaptureFixture(t)
	input.Source.State = "public_no_prefix"
	input.Source.Public.Prefix, input.Source.Public.Sources[0].Prefix = netip.Prefix{}, netip.Prefix{}
	input.Source.Public.Paths, input.Source.Public.Sources[0].Paths = nil, nil
	input.Source.Fields, input.Source.NextHops = nil, nil
	objects, err := freezeRoutingCapture(ctx, input, publicCaptureBudget())
	if err != nil {
		t.Fatal("complete public absence could not be frozen", err)
	}
	got, err := decodeRoutingCapture(ctx, objects, publicCaptureBudget())
	if err != nil || !reflect.DeepEqual(got, input) || got.Source.Public.Paths != nil || len(got.Source.Public.Sources) != 1 {
		t.Fatal("public absence lost its complete original source or invented a path", got, err)
	}
	low := publicCaptureBudget()
	low.MemoryBytes = 1 << 20
	if got, err := freezeRoutingCapture(ctx, publicCaptureFixture(t), low); !errors.Is(err, ErrBGPRoutingBudget) || got.facts.payload != "" {
		t.Fatal("public capture bypassed complete binary source admission", err)
	}
}

func TestPublicCaptureKeepsDistinctSnapshotAndViewGenerationWithoutLegacyRewrite(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := publicCaptureFixture(t)
	source := &input.Source.Public.Sources[0]
	source.SnapshotID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for i := range source.Paths {
		source.Paths[i].SnapshotID = source.SnapshotID
		if source.Paths[i].View.Generation == source.SnapshotID {
			t.Fatal("independent snapshot/generation fixture accidentally aliases identities")
		}
	}
	input.Source.Public.Paths = append([]BGPPublicRoutingPath(nil), source.Paths...)
	objects, err := freezeRoutingCapture(ctx, input, publicCaptureBudget())
	if err != nil || !bytes.Contains([]byte(objects.facts.payload), []byte(`"version":4`)) {
		t.Fatal("public capture conflated its snapshot with an independent view generation", err)
	}
	got, err := decodeRoutingCapture(ctx, objects, publicCaptureBudget())
	if err != nil || !reflect.DeepEqual(got, input) {
		t.Fatal("public capture changed original snapshot/view identities or clocks", err)
	}
	// Keep both copies consistent: refusal must come from the source binding,
	// rather than only the selected-path equality check.
	for _, invalid := range []string{"", "not-a-generation", "00000000-0000-0000-0000-000000000000"} {
		source.Paths[0].View.Generation = invalid
		input.Source.Public.Paths[0].View.Generation = invalid
		if _, err := freezeRoutingCapture(ctx, input, publicCaptureBudget()); err == nil {
			t.Fatal("public capture accepted a malformed original view generation")
		}
	}
}

func TestPublicCaptureRejectsClockCohortOmissionsAndVersionDowngrades(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	objects, err := freezeRoutingCapture(ctx, publicCaptureFixture(t), publicCaptureBudget())
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"missing-clock", "clock-source", "fact-clock", "source-fact-clock", "version-downgrade"} {
		var facts routingCaptureFacts
		var clocks routingCaptureClocks
		if err := json.Unmarshal([]byte(objects.facts.payload), &facts); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(objects.clocks.payload), &clocks); err != nil {
			t.Fatal(err)
		}
		switch scenario {
		case "missing-clock":
			clocks.Source.Public = nil
		case "clock-source":
			clocks.Source.Public.Sources[0].SnapshotID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		case "fact-clock":
			facts.Data.Source.Public.AsOf = clocks.Source.Public.AsOf
		case "source-fact-clock":
			facts.Data.Source.Public.Sources[0].AsOf = clocks.Source.Public.Sources[0].AsOf
		case "version-downgrade":
			facts.Version, clocks.Version = 1, 1
		}
		bad := objects
		bad.facts, err = marshalRoutingCaptureObject(facts)
		if err != nil {
			t.Fatal(err)
		}
		clocks.FactsDigest = bad.facts.digest
		bad.clocks, err = marshalRoutingCaptureObject(clocks)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := decodeRoutingCapture(ctx, bad, publicCaptureBudget()); err == nil || got.Owner != (InterfaceRoleFlowBinding{}) {
			t.Fatal("public capture accepted omitted or mismatched original observation clocks", scenario, err)
		}
	}
	legacy, err := freezeRoutingCapture(ctx, routingCaptureFixture(t), publicCaptureBudget())
	if err != nil || bytes.Contains([]byte(legacy.facts.payload), []byte(`"Public"`)) || bytes.Contains([]byte(legacy.clocks.payload), []byte(`"Public"`)) || !bytes.Contains([]byte(legacy.facts.payload), []byte(`"version":1`)) {
		t.Fatal("public capture changed the legacy router-only wire format", err)
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	if got, err := decodeRoutingCapture(foreign, objects, publicCaptureBudget()); err == nil || got.Owner != (InterfaceRoleFlowBinding{}) {
		t.Fatal("public capture crossed the outer tenant boundary", err)
	}
}
