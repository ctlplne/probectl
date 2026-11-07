// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

func routingCaptureRowForTest(t *testing.T, tenant string, change byte) (Row, map[string]any) {
	t.Helper()
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i+1) ^ change
	}
	input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("203.0.113.1"), Destination: netip.MustParseAddr("2001:db8::1"), Protocol: "ipfix", Domain: ^uint32(0)}
	key, err := entity.FlowCaptureKey(tenant, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", digest, input)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]any{"tenant_id": tenant, "agent_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "exporter": input.Exporter.String(), "obs_domain": input.Domain, "protocol": input.Protocol, "src_addr": input.Source.String(), "dst_addr": input.Destination.String(), "bytes": uint64(99), "raw_flow_digest": hex.EncodeToString(digest[:]), "routing_capture_key": hex.EncodeToString(key[:]), "routing_captured_unix_nanos": int64(1700000000123456789)}
	row := decodeRoutingCaptureRowForTest(t, values)
	return row, values
}

func decodeRoutingCaptureRowForTest(t *testing.T, values map[string]any) Row {
	t.Helper()
	body, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	var row Row
	if err := json.Unmarshal(body, &row); err != nil {
		t.Fatal(err)
	}
	row.TS = time.Unix(1700000000, 123000000).UTC()
	row.StartTS = row.TS.Add(-time.Second)
	return row
}

func TestFlowRoutingCaptureRowsPreserveRawIdentityAndTenant(t *testing.T) {
	const first = "11111111-1111-4111-8111-111111111111"
	const second = "22222222-2222-4222-8222-222222222222"
	row, values := routingCaptureRowForTest(t, first, 0)
	body, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"raw_flow_digest", "routing_capture_key", "routing_captured_unix_nanos"} {
		if !bytes.Contains(body, []byte(`"`+name+`":`)) {
			t.Fatal("durable flow row lost original capture metadata", name)
		}
	}
	if err := validateInsertRows([]Row{row}); err != nil {
		t.Fatal("complete original routing reference refused", err)
	}
	retry := row
	retry.SrcASN, retry.DstASN = 64500, ^uint32(0)
	retry.SrcASName, retry.DstCountry = "changed enrichment", "ZZ"
	if flowRowID(row) != flowRowID(retry) {
		t.Fatal("original raw identity changed with retry enrichment")
	}
	otherRaw, _ := routingCaptureRowForTest(t, first, 1)
	otherTenant, _ := routingCaptureRowForTest(t, second, 0)
	if flowRowID(row) == flowRowID(otherRaw) || flowRowID(row) == flowRowID(otherTenant) {
		t.Fatal("raw or tenant difference collapsed a genuine flow")
	}
	memory := NewMemory()
	if err := memory.Insert(t.Context(), []Row{row, retry, otherRaw, otherTenant}); err != nil || memory.Len() != 3 {
		t.Fatal("capture identity lost retry deduplication or sibling isolation", memory.Len(), err)
	}
	var exported bytes.Buffer
	count, err := memory.ExportTenant(t.Context(), first, &exported)
	if err != nil || count != 2 || strings.Contains(exported.String(), second) || !strings.Contains(exported.String(), values["routing_capture_key"].(string)) {
		t.Fatal("tenant export lost its capture or disclosed sibling", count, err)
	}
}

func TestFlowRoutingCaptureRowsRefuseIncompleteOrForeignMetadata(t *testing.T) {
	row, values := routingCaptureRowForTest(t, "11111111-1111-4111-8111-111111111111", 0)
	if err := validateInsertRows([]Row{row}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing_digest":   func(v map[string]any) { delete(v, "raw_flow_digest") },
		"missing_key":      func(v map[string]any) { delete(v, "routing_capture_key") },
		"missing_clock":    func(v map[string]any) { delete(v, "routing_captured_unix_nanos") },
		"negative_clock":   func(v map[string]any) { v["routing_captured_unix_nanos"] = -1 },
		"foreign_tenant":   func(v map[string]any) { v["tenant_id"] = "22222222-2222-4222-8222-222222222222" },
		"foreign_sender":   func(v map[string]any) { v["agent_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
		"changed_tuple":    func(v map[string]any) { v["obs_domain"] = uint32(1) },
		"truncated_key":    func(v map[string]any) { v["routing_capture_key"] = v["routing_capture_key"].(string)[:62] },
		"uppercase_digest": func(v map[string]any) { v["raw_flow_digest"] = strings.ToUpper(v["raw_flow_digest"].(string)) },
		"wrong_key":        func(v map[string]any) { v["routing_capture_key"] = strings.Repeat("01", 32) },
	} {
		t.Run(name, func(t *testing.T) {
			copyValues := make(map[string]any, len(values))
			for key, value := range values {
				copyValues[key] = value
			}
			mutate(copyValues)
			bad := decodeRoutingCaptureRowForTest(t, copyValues)
			memory := NewMemory()
			if err := memory.Insert(t.Context(), []Row{row, bad}); err == nil || memory.Len() != 0 {
				t.Fatal("incomplete or foreign routing reference reached flow storage")
			}
		})
	}
	// Pre-feature and unsupported sources remain representable, without an
	// invented routing capture or first processing clock.
	if err := validateInsertRows([]Row{{TenantID: "legacy-tenant"}}); err != nil {
		t.Fatal("legacy flow without capture metadata was refused", err)
	}
}
