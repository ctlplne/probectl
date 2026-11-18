// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestDashboardSDKOmitsUnselectedComplianceFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{"carrier claim", DashboardCreateRequest{Definition: DashboardDefinition{CarrierClaim: &CarrierSLAReportDefinition{}}}},
		{"monthly report", DashboardCreateRequest{Definition: DashboardDefinition{ClientReport: &ClientReportDefinition{}}}},
		{"audit control", DashboardCreateRequest{Definition: DashboardDefinition{ComplianceControl: "AU.L2-3.3.1"}}},
		{"portable report", DashboardManifestImportRequest{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.body)
			if err != nil || bytes.Contains(body, []byte(`"compliance_flow"`)) || bytes.Contains(body, []byte(`"compliance_bindings"`)) {
				t.Fatalf("unselected compliance configuration went on the wire: %s (%v)", body, err)
			}
		})
	}
}

func TestDashboardSDKPreservesSelectedComplianceFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		body any
		want []string
	}{
		{"directional flow", `{"definition":{"compliance_control":"1.3.2","compliance_flow":{"lookback":"24h","protected_zone":"payments","policy":"declared policy","sources":[]}}}`,
			&DashboardCreateRequest{}, []string{`"protected_zone":"payments"`, `"compliance_flow"`}},
		{"destination bindings", `{"manifest":{"spec":{"definition":{"compliance_control":"1.3.2","compliance_flow":{"lookback":"24h","protected_zone_slot":"cardholder-data-zone","source_slots":["edge"]}}}},"compliance_bindings":{"sources":{"edge":{"context_id":"context-id","entity_id":"entity-id"}},"protected_zone":"payments"}}`,
			&DashboardManifestImportRequest{}, []string{`"protected_zone_slot":"cardholder-data-zone"`, `"compliance_bindings"`, `"entity_id":"entity-id"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := json.Unmarshal([]byte(tc.wire), tc.body); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !bytes.Contains(body, []byte(want)) {
					t.Fatalf("selected detail %q absent on the wire: %s", want, body)
				}
			}
		})
	}
}
