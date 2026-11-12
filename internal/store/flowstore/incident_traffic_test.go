// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentTrafficCompleteRowsKeepOverlappingSelectionAndTenantBudget(t *testing.T) {
	store := NewMemory()
	red, blue := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for _, tenant := range []string{red, blue} {
		rows := make([]Row, 50_001)
		for i := range rows {
			rows[i] = Row{TenantID: tenant, AgentID: "owned-flow", Exporter: "192.0.2.1", Protocol: "ipfix", ObsDomain: math.MaxUint32,
				TS: at.Add(time.Duration(i) * time.Nanosecond), StartTS: at.Add(-time.Second), SrcAddr: "203.0.113.1", DstAddr: "203.0.113.2",
				InIf: 7, OutIf: 8, Bytes: math.MaxUint64, Packets: uint64(i + 1), Sampling: 3}
		}
		if err := store.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	sources := []IncidentTrafficSource{
		{AgentID: "owned-flow", Exporter: netip.MustParseAddr("192.0.2.1"), Protocol: "ipfix", Domain: math.MaxUint32, WholeDevice: true},
		{AgentID: "owned-flow", Exporter: netip.MustParseAddr("192.0.2.1"), Protocol: "ipfix", Domain: math.MaxUint32, InterfaceIndices: []uint32{7, 8}},
	}
	for _, tenant := range []string{red, blue} {
		batch, err := NewPlanBatch(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), store, tenant, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := batch.IncidentTrafficRows(IncidentTrafficQuery{TenantID: tenant, From: at.Add(-time.Second), To: at.Add(time.Second), Sources: sources})
		batch.Close()
		if err != nil || len(rows) != 50_001 {
			t.Fatal("complete incident input was capped or multiplied by overlapping device/interfaces", len(rows), err)
		}
		for i, row := range rows {
			if row.TenantID != tenant || row.Bytes != math.MaxUint64 || row.Packets != uint64(i+1) || row.Sampling != 3 || row.ObsDomain != math.MaxUint32 {
				t.Fatal("incident traffic lost exact counters or tenant scope", i, row)
			}
		}
	}
	batch, err := NewPlanBatch(tenancy.WithTenant(t.Context(), tenancy.ID(red)), store, red, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	if out, err := batch.IncidentTrafficRows(IncidentTrafficQuery{TenantID: blue, From: at.Add(-time.Second), To: at.Add(time.Second), Sources: sources}); !errors.Is(err, ErrNoTenant) || out != nil {
		t.Fatal("a source selection replaced its batch tenant", len(out), err)
	}
	if out, err := batch.IncidentTrafficRows(IncidentTrafficQuery{TenantID: red, From: at.Add(-time.Second), To: at.Add(time.Second), Sources: sources}); err == nil || out != nil {
		t.Fatal("a failed incident batch exposed a later successful prefix")
	}
}
