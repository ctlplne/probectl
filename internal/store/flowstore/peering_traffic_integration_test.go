// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"
)

// Actual TLS ClickHouse and its independent tenant-setting reader, with the
// memory backend as a complete population oracle. Routing/role inputs are
// modeled: this proves storage joins, not current PG grants or physical senders.
func TestPeeringTrafficRealStoreKeepsWholeTenantStatesDirectionsAndOriginalClock(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	memory := NewMemory()
	for range 2 {
		tenant := uuid.NewString()
		t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, tenant) })
		ctx, query, rows := peeringTrafficFixture(t, tenant, 50_001)
		unowned := rows[0]
		unowned.Exporter = "192.0.2.2"
		unowned.RawFlowDigest = ""
		unowned.RoutingCaptureKey = ""
		unowned.RoutingCapturedUnixNanos = 0
		rows = append(rows, unowned)
		for _, backend := range []Store{memory, store} {
			if err := backend.Insert(ctx, rows); err != nil {
				t.Fatal(err)
			}
		}
		for _, direction := range []string{"inbound", "outbound"} {
			query.Data = peeringDataWithClockForTest(t, ctx, query.Data, direction, 0)
			for _, series := range []string{"raw", "rollup"} {
				query.DataSeries = series
				want, err := memory.PeeringTraffic(ctx, query)
				if err != nil {
					t.Fatal(err)
				}
				got, err := store.PeeringTraffic(ctx, query)
				if err != nil || !reflect.DeepEqual(got.Buckets, want.Buckets) || got.InputDigest != want.InputDigest || got.RoleDigest != want.RoleDigest || got.Source != series {
					t.Fatal("actual peering query lost complete owned tenant states, directions, counters or partial intervals", series, direction, err)
				}
			}
		}
		// A retained key under a different original clock is unavailable; it
		// cannot acquire the matching state's eligibility from another epoch.
		query.Data = peeringDataWithClockForTest(t, ctx, query.Data, "inbound", 1)
		query.DataSeries = "raw"
		want, err := memory.PeeringTraffic(ctx, query)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.PeeringTraffic(ctx, query)
		if err != nil || !reflect.DeepEqual(got.Buckets, want.Buckets) {
			t.Fatal("actual peering join replaced an original capture clock", err)
		}
	}
}

func peeringDataWithClockForTest(t *testing.T, ctx context.Context, data *PeeringQueryData, direction string, delta int64) *PeeringQueryData {
	t.Helper()
	rows := make([]RoutingProjection, 0, len(data.states))
	for key, states := range data.states {
		id := data.routing.byKey[key]
		fact := data.routing.facts[id]
		rows = append(rows, RoutingProjection{Scope: fact.Scope, Key: key.key, Clock: key.clock + delta, Fields: fact.Fields, SourceIDs: fact.SourceIDs, FactsID: id, Peering: &PeeringRoutingMatch{RouterID: data.target.RouterID, PeerASN: data.target.PeerASN, Source: states.Source, Destination: states.Destination}})
	}
	target := data.target
	target.Direction = direction
	result, err := NewPeeringQueryData(ctx, target, data.routing.asOf, rows, 512<<20)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
