// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

type explorerNames []ExplorerInterface

func (n explorerNames) FlowInterfaces(_ context.Context, _ string) ([]ExplorerInterface, error) {
	return n, nil
}

func explorerFixtureRow(tenant string) Row {
	ts := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return Row{TenantID: tenant, AgentID: "collector-1", Exporter: "192.0.2.1", ObsDomain: 42, Protocol: "ipfix", TS: ts, StartTS: ts.Add(-30 * time.Second), SrcAddr: "198.51.100.7", DstAddr: "2001:db8:1::8", SrcPort: 12345, DstPort: 443, Transport: "tcp", NetType: "ipv6", InIf: 7, OutIf: 8, VLAN: 100, ToS: 184, TCPFlags: 18, NextHop: "192.0.2.254", Bytes: 123, Packets: 3, Sampling: 100, BytesScaled: 12300, PacketsScaled: 300, SrcASN: 64512, SrcASName: "Test source", SrcCountry: "DE", DstASN: 64513, DstASName: "Test destination", DstCountry: "GB"}
}
func TestExplorerRegistryCoversEveryStoredFlowColumn(t *testing.T) {
	columns := map[string]bool{}
	for _, field := range flow.QueryFields() {
		if field.Derived == "" {
			columns[field.Column] = true
		}
	}
	typ := reflect.TypeFor[Row]()
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name == "tenant_id" {
			continue
		}
		if name == "-" {
			if typ.Field(i).Name == "TS" {
				name = "ts"
			} else {
				name = "start_ts"
			}
		}
		if !columns[name] {
			t.Errorf("stored field %s missing registry entry", name)
		}
		delete(columns, name)
	}
	delete(columns, "row_id") // Stored by ClickHouse and the memory dedup index.
	if len(columns) != 0 {
		t.Fatalf("registry references absent stored columns: %v", columns)
	}
}
