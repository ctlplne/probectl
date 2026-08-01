// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build isolation

package pathstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// U-026: the cross-tenant isolation gate against REAL ClickHouse for the
// path store. Runs in CI (containerized CH via PROBECTL_PATHSTORE_URL);
// skips locally when unset.
func TestClickHousePathCrossTenantIsolation(t *testing.T) {
	url := os.Getenv("PROBECTL_PATHSTORE_URL")
	if url == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_PATHSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := newClickHouse(url)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ta := fmt.Sprintf("path-iso-a-%d", now.UnixNano())
	tb := fmt.Sprintf("path-iso-b-%d", now.UnixNano())
	target := fmt.Sprintf("shared-target-%d.example", now.UnixNano())

	mk := func(ip string) *path.Path {
		return &path.Path{
			Target: target, TargetIP: ip, Mode: "icmp", MaxHops: 8, TraceCount: 1, DestinationReached: true,
			MeasurementFidelity: &path.MeasurementFidelity{
				Version: 1, ProbeTransport: "icmp", AcquisitionMode: "raw_icmp",
				TimingSource: "application_monotonic", HopVisibility: "full",
			},
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: ip, Sent: 1, Received: 1, RTTAvgMs: 1.5}}}},
		}
	}
	if err := c.Save(ctx, ta, mk("198.51.100.10")); err != nil {
		t.Fatalf("save A: %v", err)
	}
	if err := c.Save(ctx, tb, mk("192.0.2.99")); err != nil {
		t.Fatalf("save B: %v", err)
	}

	// Tenant A's latest path for the SHARED target name must be A's, never B's.
	got, ok, err := c.Latest(ctx, ta, target)
	if err != nil || !ok {
		t.Fatalf("latest A: ok=%v err=%v", ok, err)
	}
	if got.TargetIP != "198.51.100.10" {
		t.Fatalf("CROSS-TENANT LEAK: tenant A read %q", got.TargetIP)
	}
	if got.MeasurementFidelity == nil || got.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Fatalf("tenant A fidelity missing or crossed: %+v", got.MeasurementFidelity)
	}
	roundsA, err := c.History(ctx, ta, target, HistoryQuery{})
	if err != nil || len(roundsA) != 1 || roundsA[0].Path.TargetIP != "198.51.100.10" {
		t.Fatalf("history A: rounds=%+v err=%v", roundsA, err)
	}
	roundsB, err := c.History(ctx, tb, target, HistoryQuery{})
	if err != nil || len(roundsB) != 1 || roundsB[0].Path.TargetIP != "192.0.2.99" {
		t.Fatalf("history B: rounds=%+v err=%v", roundsB, err)
	}
	// Replaying B's stable round ID in A's authenticated scope must be a
	// clean miss. path_id is never authorization by itself.
	foreign, err := c.History(ctx, ta, target, HistoryQuery{IDs: []string{roundsB[0].ID}})
	if err != nil || len(foreign) != 0 {
		t.Fatalf("CROSS-TENANT HISTORY LEAK: rounds=%+v err=%v", foreign, err)
	}

	// The empty-tenant refusal (defense in depth) holds on the live store too.
	if _, _, err := c.Latest(ctx, "", target); err == nil {
		t.Fatal("unscoped Latest must refuse (ErrNoTenant)")
	}
	if _, err := c.History(ctx, "", target, HistoryQuery{}); err == nil {
		t.Fatal("unscoped History must refuse (ErrNoTenant)")
	}
}
