// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPathHealthAlertNativeSchemasKeepCanonicalInterfaceAndPrivateAuthorityOut(t *testing.T) {
	schemas, err := alertPathHealthToolSchemas()
	if err != nil || len(schemas) != 4 {
		t.Fatal("path-health tool schema is unavailable", err)
	}
	for name, raw := range schemas {
		var envelope struct {
			Definitions map[string]json.RawMessage `json:"$defs"`
		}
		if json.Unmarshal(raw, &envelope) != nil || strings.Contains(string(raw), "#/components/schemas/") {
			t.Fatal("unresolved native input", name)
		}
		if strings.Contains(string(raw), "owner_user_id") || strings.Contains(string(raw), "read_grants") || strings.Contains(string(raw), `"tenant_id"`) {
			t.Fatal("native input accepts stored authority", name)
		}
		if name == "alert_path_health_set" || name == "alert_path_health_create" {
			var source struct {
				Required   []string `json:"required"`
				Additional bool     `json:"additionalProperties"`
			}
			if json.Unmarshal(envelope.Definitions["AlertPathHealthSourceInput"], &source) != nil || source.Additional || len(source.Required) != 2 || source.Required[0] != "test_id" || source.Required[1] != "interface_id" {
				t.Fatal("native source lost exact owned interface selection", name)
			}
		}
	}
}
