// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
)

// Extend the existing retained-input proof, using its actual TLS ClickHouse
// and independent tenant-setting reader. Metadata is modeled; this helper does
// not claim an authenticated physical flow or current route capture.
func proveRoutingCaptureRowsInRealStore(t *testing.T, store *ClickHouse) {
	t.Helper()
	tenants := []string{uuid.NewString(), uuid.NewString()}
	for _, tenant := range tenants {
		t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, tenant) })
	}
	const count = 501
	rows := make([]Row, 0, count*2)
	for _, tenant := range tenants {
		for i := range count {
			row, _ := routingCaptureRowForTest(t, tenant, 0)
			row.RawFlowDigest = fmt.Sprintf("%064x", i+1)
			body, err := hex.DecodeString(row.RawFlowDigest)
			if err != nil {
				t.Fatal(err)
			}
			var digest [32]byte
			copy(digest[:], body)
			input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr(row.Exporter), Source: netip.MustParseAddr(row.SrcAddr), Destination: netip.MustParseAddr(row.DstAddr), Protocol: row.Protocol, Domain: row.ObsDomain}
			key, err := entity.FlowCaptureKey(tenant, row.AgentID, digest, input)
			if err != nil {
				t.Fatal(err)
			}
			row.RoutingCaptureKey = hex.EncodeToString(key[:])
			rows = append(rows, row)
		}
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	retry := append([]Row(nil), rows...)
	for i := range retry {
		retry[i].SrcASN = ^uint32(0)
		retry[i].SrcASName = "different retry enrichment"
	}
	if err := store.Insert(t.Context(), retry); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range tenants {
		for _, table := range []string{sharedFlowsTable, sharedFlowRollupsTable} {
			got, err := store.queryScoped(t.Context(), Target{}, tenant, "SELECT tenant_id,raw_flow_digest,routing_capture_key,toString(routing_captured_unix_nanos) AS clock FROM "+table+" FINAL ORDER BY raw_flow_digest", nil)
			if err != nil || len(got) != count {
				t.Fatal("complete captured rows lost storage, raw dedup or reader isolation", table, len(got), err)
			}
			for i, stored := range got {
				expected := rows[lane*count+i]
				if chToString(stored["tenant_id"]) != tenant || chToString(stored["raw_flow_digest"]) != expected.RawFlowDigest || chToString(stored["routing_capture_key"]) != expected.RoutingCaptureKey || chToString(stored["clock"]) != "1700000000123456789" {
					t.Fatal("stored raw or hourly reference changed complete identity or exact clock", table, i)
				}
			}
		}
	}
	if err := store.DeleteTenantBefore(t.Context(), tenants[0], rows[0].TS.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range tenants {
		got, err := store.queryScoped(t.Context(), Target{}, tenant, "SELECT raw_flow_digest,routing_capture_key,toString(routing_captured_unix_nanos) AS clock FROM "+sharedFlowRollupsTable+" FINAL", nil)
		if err != nil || len(got) != count {
			t.Fatal("capture expiry removed hourly data or changed sibling", len(got), err)
		}
		for _, stored := range got {
			if lane == 0 && (chToString(stored["raw_flow_digest"]) != "" || chToString(stored["routing_capture_key"]) != "" || chToString(stored["clock"]) != "0") {
				t.Fatal("expired original capture remained in retained hourly inputs")
			}
			if lane == 1 && (chToString(stored["routing_capture_key"]) == "" || chToString(stored["clock"]) != "1700000000123456789") {
				t.Fatal("capture expiry changed sibling original reference")
			}
		}
	}
	t.Log("real-integration: 501 distinct modeled captures per tenant, raw/hourly storage, changed-enrichment retry dedup, predicate-free row-policy reads, exact nanos and tenant expiry/sibling survival; physical sender/route remains separate")
}
