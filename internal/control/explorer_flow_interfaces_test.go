// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/store/tsdb"
)

func TestExplorerInterfaceNamesUseLatestTenantStorageScope(t *testing.T) {
	memory := tsdb.NewMemory()
	item := func(tenant, name string, at int64) tsdb.Series {
		return tsdb.Series{Metric: "probectl_device_if_in_octets", Labels: map[string]string{"tenant_id": tenant, "device": "192.0.2.1", "if_index": "7", "if_name": name}, TimeMillis: at}
	}
	if err := memory.Write(t.Context(), []tsdb.Series{item("red", "old", 1), item("red", "older-conflict", 1), item("red", "inside", 2), item("blue", "secret-blue", 3)}); err != nil {
		t.Fatal(err)
	}
	source := explorerDeviceInterfaces{server: testServer(fakePinger{}).WithTSDB(memory)}
	for _, tc := range []struct{ tenant, name string }{{"red", "inside"}, {"blue", "secret-blue"}} {
		rows, err := source.FlowInterfaces(t.Context(), tc.tenant)
		if err != nil || len(rows) != 1 || rows[0].TenantID != tc.tenant || rows[0].Name != tc.name {
			t.Fatalf("same exporter/ifIndex crossed tenant scope: %+v %v", rows, err)
		}
	}
	if err := memory.Write(t.Context(), []tsdb.Series{item("red", "conflicting", 2)}); err != nil {
		t.Fatal(err)
	}
	if rows, err := source.FlowInterfaces(t.Context(), "red"); err == nil || rows != nil {
		t.Fatalf("ambiguous latest identity silently selected: %+v %v", rows, err)
	}
}
