// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func TestAzureVNetExportImportsDirectionalCounters(t *testing.T) {
	cfg := flow.Default()
	cfg.TenantID = "tenant-a"
	cfg.NetFlow.Enabled, cfg.IPFIX.Enabled, cfg.SFlow.Enabled = false, false, false
	cfg.CloudImport = flow.CloudImportConfig{Provider: "azure_vnet_flow_logs", Path: "-"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	const record = `{
       "category":"FlowLogFlowEvent", "flowLogVersion":%d,
       "time":"2026-06-30T12:00:01Z", "tenant_id":"payload-claimed-tenant",
       %s,
       "macAddress":"0242AABBCCDD",
       "flowRecords":{"flows":[{"flowGroups":[{"flowTuples":[%s]}]}]}
       }`
	const target = `"targetResourceID":"/subscriptions/demo/resourceGroups/Fixture/providers/Microsoft.Network/virtualNetworks/Blue"`
	const oldTarget = `"resourceId":"/subscriptions/demo/resourceGroups/Fixture/providers/Microsoft.Network/flowLogs/Old"`
	const v4Tuples = `"1782820800,10.0.0.4,192.0.2.12,49342,443,6,O,B,NX,,,,",
       "1782820800,10.0.0.4,192.0.2.12,49342,443,6,O,C,NX,5,100,2,560",
       "1782820800,10.0.0.4,198.51.100.44,1234,80,6,O,D,NX,12,100,30,999",
       "1782820800,10.0.0.4,203.0.113.19,1234,80,6,O,C,NX,1,18446744073709551616,0,0"`
	const v5Tuple = `"1782820800456,2001:db8:1::10,2001:db8:2::10,49500,53,17,I,E,X,0,0,9,700,1,10.0.0.5,40000"`
	const v2Tuple = `"1782820800,10.0.0.4,192.0.2.66,0,0,1,I,E,NX,1,64,,"`
	const overflowEpoch = `"9999999999999,10.0.0.4,192.0.2.44,49200,443,6,O,C,NX,8,20,0,0"`
	export := fmt.Sprintf("{\n\"records\":[%s,%s,%s,%s,%s]\n}",
		fmt.Sprintf(record, 4, target, v4Tuples),
		fmt.Sprintf(record, 99, target, v4Tuples),
		fmt.Sprintf(record, 4, target, overflowEpoch),
		fmt.Sprintf(record, 5, target, v5Tuple),
		fmt.Sprintf(record, 2, oldTarget, v2Tuple))
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	if _, err := z.Write([]byte(export)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	em := &captureEmitter{}
	inserted, malformed, err := Emit(t.Context(), Provider(cfg.CloudImport.Provider), cfg.TenantID, "azure-source", &compressed, em)
	if err != nil || inserted != 4 || malformed != 3 || len(em.recs) != 4 {
		t.Fatalf("imported=%d malformed=%d emitted=%d err=%v", inserted, malformed, len(em.recs), err)
	}
	want := []struct {
		src, dst       string
		sport, dport   uint16
		packets, bytes uint64
		millis         int64
		resource       string
	}{
		{"10.0.0.4", "192.0.2.12", 49342, 443, 5, 100, 1782820800000, "virtualnetworks/blue"},
		{"192.0.2.12", "10.0.0.4", 443, 49342, 2, 560, 1782820800000, "virtualnetworks/blue"},
		{"2001:db8:2::10", "2001:db8:1::10", 53, 49500, 9, 700, 1782820800456, "virtualnetworks/blue"},
		{"10.0.0.4", "192.0.2.66", 0, 0, 1, 64, 1782820800000, "flowlogs/old"},
	}
	for i, expected := range want {
		r := em.recs[i]
		if r.TenantID != cfg.TenantID || r.AgentID != "azure-source" || r.Protocol != flow.ProtoAzureVNetFlowLogs ||
			!strings.HasSuffix(r.Exporter, "/"+expected.resource+":0242aabbccdd") ||
			r.SrcAddr.String() != expected.src || r.DstAddr.String() != expected.dst ||
			r.SrcPort != expected.sport || r.DstPort != expected.dport || r.Bytes != expected.bytes || r.Packets != expected.packets ||
			!r.Start.Equal(time.UnixMilli(expected.millis)) || !r.End.Equal(r.Start) || r.SamplingRate != 1 {
			t.Fatalf("row %d = %+v, expected %+v", i, r, expected)
		}
	}

	for _, invalid := range []string{`{"records":[]`, `{"records":[],"records":[]}`, `{"records":[]} {}`, `{"flowRecords":{}}`} {
		em := &captureEmitter{}
		if n, _, err := Emit(t.Context(), ProviderAzureVNet, cfg.TenantID, "Azure", strings.NewReader(invalid), em); n != 0 || err == nil {
			t.Errorf("invalid export admitted: %s, %d, %v", invalid, n, err)
		}
	}
}
