// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestLibreNMSFiniteAlertSelectorStaysInertAndRejectsChangedSemantics(t *testing.T) {
	// Independent expected output from the pinned 26.10.2 parser's one-rule
	// devices/ports relationship path; the real-vendor test checks the API.
	const sourceQuery = `SELECT * FROM devices,ports WHERE (devices.device_id = ? AND devices.device_id = ports.device_id) AND ports.ifOperStatus != "up"`
	base := `{"status":"ok","rules":[{"id":31,"name":"Port down","severity":"critical",` +
		`"devices":[17],"groups":[],"locations":[],"invert_map":0,"disabled":1,` +
		`"builder":{"condition":"AND","rules":[{"id":"ports.ifOperStatus",` +
		`"field":"ports.ifOperStatus","type":"string","input":"text",` +
		`"operator":"not_equal","value":"up"}],"valid":true},` +
		`"query":` + strconv.Quote(sourceQuery) + `,` +
		`"extra":{"options":{"override_query":false}},` +
		`"operations":[{"transport":"source-only-secret"}]}]}`
	for _, tc := range []struct {
		name, before, after, parent string
	}{
		{"finite", "", "", "17"},
		{"global selector", `"devices":[17]`, `"devices":[]`, ""},
		{"multiple devices", `"devices":[17]`, `"devices":[17,18]`, ""},
		{"group selector", `"groups":[]`, `"groups":[7]`, ""},
		{"location selector", `"locations":[]`, `"locations":[5]`, ""},
		{"inverted selector", `"invert_map":0`, `"invert_map":1`, ""},
		{"active source", `"disabled":1`, `"disabled":0`, ""},
		{"custom query", `"override_query":false`, `"override_query":true`, ""},
		{"extra source mode", `"override_query":false`, `"override_query":false,"recovery":true`, ""},
		{"query differs", strconv.Quote(sourceQuery), strconv.Quote(sourceQuery + ` OR 1=1`), ""},
		{"changed predicate", `"value":"up"`, `"value":"down"`, ""},
		{"second predicate", `"valid":true`, `"valid":true,"condition2":"OR"`, ""},
		{"unknown severity", `"severity":"critical"`, `"severity":"ok"`, ""},
		{"missing selector", `"groups":[],`, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := base
			if tc.before != "" {
				if !strings.Contains(raw, tc.before) {
					t.Fatal("test mutation anchor absent")
				}
				raw = strings.Replace(raw, tc.before, tc.after, 1)
			}
			got, err := parseLibreNMSRules(strings.NewReader(raw))
			if err != nil || len(got.Rows) != 1 {
				t.Fatalf("source rule did not remain a review row: %v", err)
			}
			row := got.Rows[0]
			if row.ParentID != tc.parent || !contains(row.UnmappedCodes, "expression_unmapped") ||
				!contains(row.UnmappedCodes, "delivery_unmapped") {
				t.Fatalf("source selector or inert state changed: %+v", row)
			}
			wire, err := json.Marshal(got)
			if err != nil || strings.Contains(string(wire), "SELECT *") ||
				strings.Contains(string(wire), "source-only-secret") ||
				strings.Contains(string(wire), `"builder"`) {
				t.Fatalf("source SQL or operation escaped into review: %v", err)
			}
		})
	}
}
