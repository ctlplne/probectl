// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestRetainedRoutingQueryFieldsKeepWholePathsAndExplicitAmbiguity(t *testing.T) {
	proveRoutingQueryCaptureReuseKeepsEveryOriginalReference(t)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	lookup := routingCaptureFixture(t)
	path := lookup.Source.Route.Paths[0]
	values := make([]uint32, 65_537)
	for i := range values {
		values[i] = uint32(i + 1)
	}
	values[len(values)-1] = ^uint32(0)
	path.Segments = []BGPRoutingSegment{{Kind: 2, Values: values}}
	lookup.Source.Route.Paths = []BGPRoutingChange{path}
	fields, err := routingFlowPathFields(ctx, lookup.Source.Route.Paths, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	lookup.Source.Fields = fields
	ref := BGPRoutingCaptureReference{Key: [32]byte{31: 1}, CapturedAt: lookup.CapturedAt}
	projection, err := routingCaptureQueryProjection(ctx, lookup, ref, routingViewBudget())
	encoded, _ := json.Marshal([]string{fields[0].ASPathText})
	if err != nil || projection.Scope != lookup.Owner.Scope || projection.Key != ref.Key || projection.Clock != ref.CapturedAt.UnixNano() || len(projection.Fields) != 14 || projection.Fields["src_bgp_as_paths"] != string(encoded) || projection.Fields["src_bgp_origin_as"] != "4294967295" || projection.Fields["src_bgp_first_transit_as"] != "1" || projection.Fields["src_bgp_next_hop_as"] != "65010" || projection.Fields["src_bgp_rpki"] != "unknown" {
		t.Fatal("retained routing query lost complete paths, full ASN or original identity", err)
	}
	for _, source := range []string{lookup.Owner.SourceID, "routing-view/" + lookup.Source.Route.View.ID + "/" + lookup.Source.Route.View.Generation, lookup.Source.NextHops[0].Sources[0]} {
		found := false
		for _, got := range projection.SourceIDs {
			found = found || source == got
		}
		if !found {
			t.Fatal("retained query omitted independent source provenance", source)
		}
	}
	// A second complete path with a different known endpoint is ambiguous.
	other := path
	other.HasPathID = true
	other.PathID++
	other.Segments = []BGPRoutingSegment{{Kind: 2, Values: []uint32{65000, 64500}}}
	lookup.Source.Route.Paths = append(lookup.Source.Route.Paths, other)
	lookup.Source.Fields, err = routingFlowPathFields(ctx, lookup.Source.Route.Paths, routingViewBudget())
	if err != nil {
		t.Fatal(err)
	}
	lookup.Source.NextHops = append(lookup.Source.NextHops, BGPRoutingNextHopAS{Reason: "current_source_unavailable"})
	projection, err = routingCaptureQueryProjection(ctx, lookup, ref, routingViewBudget())
	var paths []string
	decodeErr := json.Unmarshal([]byte(projection.Fields["src_bgp_as_paths"]), &paths)
	if err != nil || decodeErr != nil || len(paths) != 2 || !strings.Contains(projection.Fields["src_bgp_as_paths"], "4294967295") || projection.Fields["src_bgp_origin_as"] != "" || projection.Fields["src_bgp_first_transit_as"] != "" || projection.Fields["src_bgp_next_hop_as"] != "" {
		t.Fatal("retained routing query guessed a multipath endpoint or dropped a full path", err, decodeErr)
	}
	lookup.Source = BGPRoutingFlowSide{State: "no_prefix"}
	lookup.Destination = BGPRoutingFlowSide{State: "source_unavailable"}
	projection, err = routingCaptureQueryProjection(ctx, lookup, ref, routingViewBudget())
	if err != nil || projection.Fields["src_bgp_provenance"] != "no_prefix" || projection.Fields["dst_bgp_provenance"] != "unavailable" || projection.Fields["src_bgp_as_paths"] != "" || projection.Fields["dst_bgp_origin_as"] != "" || projection.Fields["dst_bgp_rpki"] != "unknown" {
		t.Fatal("retained routing query invented missing route evidence", err)
	}
	for _, tenant := range []string{"", "99999999-9999-4999-8999-999999999999"} {
		if got, err := routingCaptureQueryProjection(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), lookup, ref, routingViewBudget()); !errors.Is(err, entity.ErrScopeMismatch) || !reflect.DeepEqual(got, flowstore.RoutingProjection{}) {
			t.Fatal("retained routing projection crossed tenant", err)
		}
	}
	if got, err := routingCaptureQueryProjection(ctx, lookup, ref, BGPRoutingBudget{MemoryBytes: 1, WorkUnits: 1}); !errors.Is(err, ErrBGPRoutingBudget) || !reflect.DeepEqual(got, flowstore.RoutingProjection{}) {
		t.Fatal("retained routing query exposed an unadmitted prefix", err)
	}
}

func proveRoutingQueryCaptureReuseKeepsEveryOriginalReference(t *testing.T) {
	t.Helper()
	lookup := routingCaptureFixture(t)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	input := entity.FlowCaptureInput{Exporter: lookup.Owner.Exporter, Protocol: lookup.Owner.Protocol, Domain: lookup.Owner.Domain, Source: lookup.Source.Route.Prefix.Addr(), Destination: lookup.Destination.Route.Prefix.Addr()}
	reads := make([]flowstore.RoutingCaptureRead, 50_000)
	header := routingQueryCaptureHeader{contextID: lookup.Owner.ContextID}
	for i := range reads {
		read := flowstore.RoutingCaptureRead{Sender: lookup.Owner.AgentID, Witness: entity.FlowCaptureWitness{Input: input}}
		binary.BigEndian.PutUint64(read.Witness.RawDigest[:8], uint64(i+1))
		key, err := entity.FlowCaptureKey(routingCaptureTenant, read.Sender, read.Witness.RawDigest, input)
		if err != nil {
			t.Fatal(err)
		}
		read.Ref = entity.FlowCaptureReference{Key: key, CapturedAt: lookup.CapturedAt.Add(time.Duration(i) * time.Nanosecond)}
		if !routingQueryCaptureMatches(lookup, read, header) {
			t.Fatal("shared routing capture lost an original valid reference", i)
		}
		reads[i] = read
	}
	budget := BGPRoutingBudget{MemoryBytes: flowstore.DefaultExplorerBudget().MemoryBytes / 4, WorkUnits: flowstore.DefaultExplorerBudget().MemoryBytes / 4}
	keys, err := routingQueryCaptureKeys(ctx, tenancy.Scope{Tenant: tenancy.ID(routingCaptureTenant)}, reads, &budget)
	if err != nil || len(keys) != len(reads) {
		t.Fatal("complete routing query capture references were truncated", err)
	}
	changed := reads[len(reads)-1]
	changed.Witness.RawDigest[0] ^= 1
	if partial, err := routingQueryCaptureKeys(ctx, tenancy.Scope{Tenant: tenancy.ID(routingCaptureTenant)}, []flowstore.RoutingCaptureRead{reads[0], changed}, &budget); !errors.Is(err, entity.ErrScopeMismatch) || partial != nil {
		t.Fatal("shared routing capture accepted a detached original digest", err)
	}
	for _, change := range []func(*flowstore.RoutingCaptureRead){
		func(read *flowstore.RoutingCaptureRead) { read.Sender = "another-agent" },
		func(read *flowstore.RoutingCaptureRead) { read.Witness.Input.Protocol = "sflow5" },
		func(read *flowstore.RoutingCaptureRead) { read.Ref.CapturedAt = lookup.Owner.ValidUntil },
		func(read *flowstore.RoutingCaptureRead) {
			read.Ref.CapturedAt = lookup.Source.Route.AsOf.Add(-time.Nanosecond)
		},
	} {
		changed := reads[0]
		change(&changed)
		if routingQueryCaptureMatches(lookup, changed, header) {
			t.Fatal("shared routing capture reused another sender, tuple or invalid first clock")
		}
	}
}
