// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingRPKIEnricher(t testing.TB, at time.Time, rows string) *opendata.Enricher {
	t.Helper()
	file := filepath.Join(t.TempDir(), "validator.json")
	raw := fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[%s]}`, at.Add(-time.Minute).Unix(), rows)
	if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := opendata.LoadRPKIVRPs(t.Context(), file, time.Hour, 2<<30, 8<<30, at)
	if err != nil {
		t.Fatal(err)
	}
	en := opendata.NewEnricher(nil)
	en.Register(source)
	return en
}

func routingRPKIKnownFixture(t testing.TB) BGPRoutingFlowLookup {
	t.Helper()
	lookup := routingCaptureFixture(t)
	for _, side := range []*BGPRoutingFlowSide{&lookup.Source, &lookup.Destination} {
		side.Route.Paths = append([]BGPRoutingChange(nil), side.Route.Paths...)
		for i := range side.Route.Paths {
			path := &side.Route.Paths[i]
			path.Segments = append(append([]BGPRoutingSegment(nil), path.Segments...), BGPRoutingSegment{Kind: 2, Values: []uint32{^uint32(0)}})
		}
		var err error
		side.Fields, err = routingFlowPathFields(t.Context(), side.Route.Paths, publicCaptureBudget())
		if err != nil {
			t.Fatal(err)
		}
	}
	return lookup
}

func TestRoutingRPKICaptureKeepsWholeEvidenceOriginalClockAndTenantBoundary(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	lookup := routingRPKIKnownFixture(t)
	var rows strings.Builder
	const count = 5001
	for i := range count {
		if i != 0 {
			rows.WriteByte(',')
		}
		asn := uint32(i)
		if i == count-1 {
			asn = ^uint32(0)
		}
		fmt.Fprintf(&rows, `{"prefix":"192.0.2.0/24","asn":%d,"maxLength":32}`, asn)
	}
	en := routingRPKIEnricher(t, lookup.CapturedAt, rows.String())
	if err := captureRoutingRPKI(ctx, &lookup, en.RPKI(lookup.CapturedAt), publicCaptureBudget()); err != nil || lookup.Source.RPKI == nil || len(lookup.Source.RPKI.Covering) != count || lookup.Source.RPKI.Records != count || !reflect.DeepEqual(lookup.Source.RPKI.Verdicts, []string{"valid"}) {
		t.Fatal("RPKI capture lost whole original validator evidence", err)
	}
	objects, err := freezeRoutingCapture(ctx, lookup, publicCaptureBudget())
	if err != nil || !strings.Contains(objects.facts.payload, `"version":3`) {
		t.Fatal("complete RPKI evidence failed immutable capture", err)
	}
	got, err := decodeRoutingCapture(ctx, objects, publicCaptureBudget())
	if err != nil || !reflect.DeepEqual(got, lookup) {
		t.Fatal("RPKI capture changed original source generation or complete paths", err)
	}
	ref := BGPRoutingCaptureReference{Key: [32]byte{31: 1}, CapturedAt: lookup.CapturedAt}
	projection, err := routingCaptureQueryProjection(ctx, got, ref, publicCaptureBudget())
	if err != nil || projection.Fields["src_bgp_rpki"] != "valid" || projection.Fields["dst_bgp_rpki"] != "valid" || !slices.Contains(projection.SourceIDs, "rpki-vrps/"+lookup.Source.RPKI.Version) {
		t.Fatal("RPKI native projection lost original independent evidence", err, projection)
	}
	// New sources and wall-clock age do not refill an original accepted flow.
	newer := routingRPKIEnricher(t, lookup.CapturedAt.Add(2*time.Hour), "")
	if newer.RPKI(lookup.CapturedAt.Add(2*time.Hour)).Version == lookup.Source.RPKI.Version {
		t.Fatal("changed validator generation lost identity")
	}
	again, err := decodeRoutingCapture(ctx, objects, publicCaptureBudget())
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatal("later validator source refilled original RPKI capture", err)
	}
	foreign := tenancy.WithTenant(t.Context(), tenancy.ID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
	if got, err := decodeRoutingCapture(foreign, objects, publicCaptureBudget()); err == nil || got.Source.RPKI != nil {
		t.Fatal("RPKI capture crossed outer storage tenant boundary", err)
	}
}

func TestRoutingRPKICaptureRefusesForgedStalePartialAndUnadmittedEvidence(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	lookup := routingRPKIKnownFixture(t)
	en := routingRPKIEnricher(t, lookup.CapturedAt, `{"prefix":"192.0.2.0/24","asn":4294967295,"maxLength":32}`)
	snapshot := en.RPKI(lookup.CapturedAt)
	for _, mutate := range []func(*BGPRoutingRPKICapture){
		func(c *BGPRoutingRPKICapture) { c.Verdicts[0] = "invalid" },
		func(c *BGPRoutingRPKICapture) { c.Covering = nil },
		func(c *BGPRoutingRPKICapture) { c.Records = 0 },
		func(c *BGPRoutingRPKICapture) { c.Prefix = netip.MustParsePrefix("203.0.113.0/24") },
		func(c *BGPRoutingRPKICapture) { c.ObservedAt = lookup.CapturedAt.Add(time.Second) },
		func(c *BGPRoutingRPKICapture) { c.ValidUntil = lookup.CapturedAt },
		func(c *BGPRoutingRPKICapture) { c.Covering[0].MaxLength = 23 },
		func(c *BGPRoutingRPKICapture) { c.Covering = append(c.Covering, c.Covering[0]) },
		func(c *BGPRoutingRPKICapture) { c.Version = "unproved" },
	} {
		copy := lookup
		if err := captureRoutingRPKI(ctx, &copy, snapshot, publicCaptureBudget()); err != nil {
			t.Fatal(err)
		}
		mutate(copy.Source.RPKI)
		if objects, err := freezeRoutingCapture(ctx, copy, publicCaptureBudget()); err == nil || objects.facts.payload != "" {
			t.Fatal("RPKI capture accepted forged or stale independent evidence", err)
		}
	}
	for _, limits := range []BGPRoutingBudget{{MemoryBytes: 1, WorkUnits: 1 << 30}, {MemoryBytes: 1 << 30, WorkUnits: 1}} {
		copy := lookup
		if err := captureRoutingRPKI(ctx, &copy, snapshot, limits); err == nil || copy.Source.RPKI != nil || copy.Destination.RPKI != nil {
			t.Fatal("unadmitted RPKI operation returned a partial capture", err)
		}
	}
	for _, absent := range []opendata.RPKISnapshot{en.RPKI(lookup.CapturedAt.Add(2 * time.Hour)), {Enabled: true, Current: true, Version: snapshot.Version}} {
		copy := lookup
		if err := captureRoutingRPKI(ctx, &copy, absent, publicCaptureBudget()); err != nil || copy.Source.RPKI != nil {
			t.Fatal("stale or caller-filled validator metadata established authority", err)
		}
	}
}

func TestRoutingRPKICapturePreservesUnknownPublicOriginsAndCompleteNotFound(t *testing.T) {
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(routingCaptureTenant))
	mixed := routingRPKIKnownFixture(t)
	other := mixed.Source.Route.Paths[0]
	other.PathID--
	other.Segments = append(append([]BGPRoutingSegment(nil), other.Segments...), BGPRoutingSegment{Kind: 2, Values: []uint32{64496}})
	mixed.Source.Route.Paths = append(mixed.Source.Route.Paths, other)
	mixed.Source.NextHops = append(mixed.Source.NextHops, mixed.Source.NextHops[0])
	var err error
	mixed.Source.Fields, err = routingFlowPathFields(ctx, mixed.Source.Route.Paths, publicCaptureBudget())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		input BGPRoutingFlowLookup
		rows  string
		want  string
	}{
		{publicCaptureFixture(t), "", "unknown"}, // original AS_SET has no unique origin
		{routingRPKIKnownFixture(t), "", "not_found"},
		{routingRPKIKnownFixture(t), `{"prefix":"192.0.2.0/24","asn":64496,"maxLength":32}`, "invalid"},
		{mixed, `{"prefix":"192.0.2.0/24","asn":4294967295,"maxLength":32}`, "unknown"},
	} {
		input := tc.input
		en := routingRPKIEnricher(t, input.CapturedAt, tc.rows)
		if err := captureRoutingRPKI(ctx, &input, en.RPKI(input.CapturedAt), publicCaptureBudget()); err != nil {
			t.Fatal(err)
		}
		ref := BGPRoutingCaptureReference{Key: [32]byte{31: 1}, CapturedAt: input.CapturedAt}
		projection, err := routingCaptureQueryProjection(ctx, input, ref, publicCaptureBudget())
		if err != nil || projection.Fields["src_bgp_rpki"] != tc.want || input.Source.RPKI == nil {
			t.Fatal("complete empty source or ambiguous origin invented a validation verdict", tc.want, projection, err)
		}
		if len(input.Source.Fields) == 2 && !reflect.DeepEqual(input.Source.RPKI.Verdicts, []string{"valid", "invalid"}) {
			t.Fatal("RPKI multipath consensus clipped or guessed original path verdicts", input.Source.RPKI.Verdicts)
		}
		objects, err := freezeRoutingCapture(ctx, input, publicCaptureBudget())
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal([]byte(objects.facts.payload), &value); err != nil || value["version"] != float64(3) {
			t.Fatal("RPKI capture omitted its independent evidence format", err)
		}
	}
}
