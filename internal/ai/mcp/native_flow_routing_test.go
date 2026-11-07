// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestNativeRoutingASNsKeepStructuredPathsAndMandatoryTextRedaction(t *testing.T) {
	const cardLikePath = "4111 1111 1111 1111"
	value, _ := json.Marshal([]string{cardLikePath})
	input := NativeFlowResult{Rows: []NativeFlowRow{{Group: []NativeFlowDimension{
		{Field: "src_bgp_as_paths", Value: string(value), RoutingPaths: []NativeFlowRoutingPath{{Segments: []NativeFlowRoutingSegment{{Kind: 2, ASNs: []uint32{4111, 1111, 1111, 1111}}, {Kind: 1, ASNs: []uint32{^uint32(0), 0}}}}}},
		{Field: "protocol", Value: "password=local-fixture-only " + cardLikePath},
	}}}}
	complete := make([]uint32, 65_538)
	for i := range complete {
		complete[i] = 64500
	}
	complete[len(complete)-1] = ^uint32(0)
	input.Rows[0].Group[0].RoutingPaths[0].Segments = append(input.Rows[0].Group[0].RoutingPaths[0].Segments, NativeFlowRoutingSegment{Kind: 2, ASNs: complete})
	server := nativeProbeServer(&nativeBackendProbe{}, nil)
	response, err := server.redactedToolResult("routing-fixture", input, true)
	if err != nil {
		t.Fatal(err)
	}
	raw := response["structuredContent"].(json.RawMessage)
	if bytes.Contains(raw, []byte(cardLikePath)) || bytes.Contains(raw, []byte("local-fixture-only")) {
		t.Fatal("native routing metadata bypassed mandatory free-text redaction")
	}
	var got NativeFlowResult
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal("native routing redaction damaged structured protocol values", err)
	}
	if !reflect.DeepEqual(got.Rows[0].Group[0].RoutingPaths, input.Rows[0].Group[0].RoutingPaths) {
		t.Fatal("native routing redaction lost exact ASNs, order or segment kinds")
	}
	csv := NativeFlowCSVResult{
		RecordOffset: 50000, TotalRecords: 50001,
		Columns:      []string{"record_type", "src_bgp_as_paths", "label"},
		Records:      [][]string{{"detail", string(value), "password=local-fixture-only"}},
		RoutingCells: []NativeFlowCSVRoutingCell{{Record: 50000, Column: 1, Paths: input.Rows[0].Group[0].RoutingPaths}},
	}
	csvResponse, err := server.redactedToolResult("routing-fixture", csv, true)
	if err != nil {
		t.Fatal(err)
	}
	csvRaw := csvResponse["structuredContent"].(json.RawMessage)
	var csvCopy NativeFlowCSVResult
	if err := json.Unmarshal(csvRaw, &csvCopy); err != nil || !reflect.DeepEqual(csvCopy.RoutingCells, csv.RoutingCells) || bytes.Contains(csvRaw, []byte(cardLikePath)) || bytes.Contains(csvRaw, []byte("local-fixture-only")) {
		t.Fatal("native CSV routing facts lost complete values or bypassed mandatory text redaction", err)
	}
	content := response["content"].([]map[string]any)
	var copy NativeFlowResult
	if err := json.Unmarshal([]byte(content[0]["text"].(string)), &copy); err != nil || !reflect.DeepEqual(copy, got) {
		t.Fatal("native routing wire copies diverged", err)
	}
}
