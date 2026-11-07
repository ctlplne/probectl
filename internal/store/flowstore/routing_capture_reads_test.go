// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingReferencePopulation(t *testing.T, tenant string, count int) ([]Row, []map[string]any) {
	t.Helper()
	rows := make([]Row, count)
	wire := make([]map[string]any, count)
	for i := range rows {
		row, source := routingCaptureRowForTest(t, tenant, 0)
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
		source["raw_flow_digest"], source["routing_capture_key"] = row.RawFlowDigest, row.RoutingCaptureKey
		source["obs_domain"] = strconv.FormatUint(uint64(row.ObsDomain), 10)
		source["routing_captured_unix_nanos"] = strconv.FormatInt(row.RoutingCapturedUnixNanos, 10)
		rows[i], wire[i] = row, source
	}
	return rows, wire
}

func TestRoutingCaptureReferenceReadsKeepCompleteOriginalScopeAndAdmission(t *testing.T) {
	const count = 1001
	tenants := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	st := NewMemory()
	for _, tenant := range tenants {
		rows, wire := routingReferencePopulation(t, tenant, count)
		if err := st.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		got, err := st.routingCaptureReferences(ctx, tenant, rows[0].TS.Add(-time.Second), rows[0].TS.Add(time.Second), "raw")
		if err != nil || len(got) != count {
			t.Fatal("routing reference read truncated the complete original population", len(got), err)
		}
		decoded, err := decodeRoutingReads(ctx, tenant, wire, 16<<20)
		if err != nil || len(decoded) != count {
			t.Fatal("routing reference wire lost full original values", len(decoded), err)
		}
		for i, read := range got {
			if read != decoded[i] || read.Ref.CapturedAt.UnixNano() != rows[0].RoutingCapturedUnixNanos || read.Witness.Input.Domain != ^uint32(0) {
				t.Fatal("routing reference read changed order, exact clock or full source domain", i)
			}
		}
		if partial, err := st.routingCaptureReferences(ctx, tenants[1], rows[0].TS.Add(-time.Second), rows[0].TS.Add(time.Second), "raw"); tenant == tenants[0] && (!errors.Is(err, ErrNoTenant) || partial != nil) {
			t.Fatal("routing reference reader accepted a foreign tenant context", err)
		}
		wire[len(wire)-1]["tenant_id"] = tenants[1]
		if partial, err := decodeRoutingReads(ctx, tenants[0], wire, 16<<20); partial != nil || err == nil {
			t.Fatal("foreign late routing reference exposed a partial population")
		}
	}
	budget := DefaultExplorerBudget()
	budget.ReadRows = count - 1
	if err := AttachExplorerBudget(st, budget); err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenants[0]))
	at := time.Unix(1700000000, 123000000).UTC()
	if partial, err := st.routingCaptureReferences(ctx, tenants[0], at.Add(-time.Second), at.Add(time.Second), "raw"); !errors.Is(err, ErrExplorerBudget) || partial != nil {
		t.Fatal("routing reference admission returned a truncated prefix", err)
	}
	if _, err := routingReadFromRow(Row{}); err == nil {
		t.Fatal("legacy empty metadata invented an original routing reference")
	}
}
