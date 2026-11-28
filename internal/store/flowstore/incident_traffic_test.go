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

	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestIncidentTrafficCompleteRowsKeepOverlappingSelectionAndTenantBudget(t *testing.T) {
	store := NewMemory()
	red, blue := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	ports := map[string]uint16{red: 443, blue: 8443}
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for _, tenant := range []string{red, blue} {
		rows := make([]Row, 50_001)
		for i := range rows {
			rows[i] = Row{TenantID: tenant, AgentID: "owned-flow", Exporter: "192.0.2.1", Protocol: "ipfix", ObsDomain: math.MaxUint32,
				TS: at.Add(time.Duration(i) * time.Nanosecond), StartTS: at.Add(-time.Second), SrcAddr: "203.0.113.1", DstAddr: "203.0.113.2", DstPort: ports[tenant],
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
			if row.TenantID != tenant || row.DstPort != ports[tenant] || row.Bytes != math.MaxUint64 || row.Packets != uint64(i+1) || row.Sampling != 3 || row.ObsDomain != math.MaxUint32 {
				t.Fatal("incident traffic lost the destination port, exact counters or tenant scope", i, row)
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

func TestIncidentTrafficDecodesDestinationPortAndRejectsIncompleteRows(t *testing.T) {
	value := map[string]any{
		"tenant_id": "owned", "agent_id": "collector", "exporter": "192.0.2.1", "protocol": "ipfix", "obs_domain": "42",
		"src_addr": "198.51.100.1", "dst_addr": "203.0.113.1", "dst_port": "65535", "in_if": "1", "out_if": "2",
		"raw_bytes": "123", "raw_packets": "3", "sampling": "1", "time_nanos": "20", "start_nanos": "10", "routing_captured_unix_nanos": "0",
	}
	row, err := decodeIncidentTrafficRow("owned", value)
	if err != nil || row.DstPort != math.MaxUint16 {
		t.Fatal("valid stored port was lost", row.DstPort, err)
	}
	if _, err := decodeIncidentTrafficRow("sibling", value); !errors.Is(err, errIncidentTrafficRow) {
		t.Fatal("stored destination port escaped its tenant scope", err)
	}
	for _, port := range []string{"65536", ""} {
		value["dst_port"] = port
		if _, err := decodeIncidentTrafficRow("owned", value); !errors.Is(err, errIncidentTrafficRow) {
			t.Fatal("invalid stored port was interpreted as a valid observation", port, err)
		}
	}
}

func TestRetainedIncidentTrafficKeysCannotExpandSourceOrTenant(t *testing.T) {
	st := NewMemory()
	var owned [2][]Row
	for lane, tenant := range []string{"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"} {
		rows, _ := routingReferencePopulation(t, tenant, 2)
		for i := range rows {
			rows[i].Sampling = 1
			rows[i].ClockBasis = flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL
		}
		owned[lane] = rows
		if err := st.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	for lane, rows := range owned {
		proveRetainedIncidentTrafficKeys(t, st, rows[0], rows[1], owned[1-lane][0])
	}
}

func proveRetainedIncidentTrafficKeys(t *testing.T, backend Store, selected, unselected, sibling Row) {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(selected.TenantID))
	batch, err := NewPlanBatch(ctx, backend, selected.TenantID, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	query := IncidentTrafficQuery{TenantID: selected.TenantID, From: selected.TS.Add(-time.Second), To: selected.TS.Add(time.Second), Series: "raw",
		RetainedKeys: []string{selected.RoutingCaptureKey, sibling.RoutingCaptureKey}, IncludeClockBasis: true,
		Sources: []IncidentTrafficSource{{AgentID: selected.AgentID, Exporter: netip.MustParseAddr(selected.Exporter), Protocol: selected.Protocol, Domain: selected.ObsDomain, WholeDevice: true}}}
	rows, err := batch.IncidentTrafficRows(query)
	if err != nil || len(rows) != 1 || rows[0].TenantID != selected.TenantID || rows[0].RoutingCaptureKey != selected.RoutingCaptureKey || rows[0].RoutingCaptureKey == unselected.RoutingCaptureKey {
		t.Fatal("exact capture read added an unselected key or sibling tenant", rows, err)
	}
	if rows[0].ClockBasis != selected.ClockBasis || rows[0].ClockBasis == 0 || rows[0].NextHop != "" {
		t.Fatal("exact capture read changed clock provenance or exposed a next hop")
	}
	query.Sources[0].Domain ^= 1
	if rows, err := batch.IncidentTrafficRows(query); err != nil || len(rows) != 0 {
		t.Fatal("exact capture read expanded the selected source", rows, err)
	}
}
