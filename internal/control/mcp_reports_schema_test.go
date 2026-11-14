// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"testing"
)

func TestNativeReportScheduleConsentDoesNotRequireEnabled(t *testing.T) {
	schemas, err := reportToolSchemas()
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		AnyOf      []struct {
			Required []string `json:"required"`
		} `json:"anyOf"`
	}
	if err := json.Unmarshal(schemas["report_schedule_update"], &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Required) != 1 || schema.Required[0] != "id" {
		t.Fatal("native consent cannot be changed independently of schedule enablement")
	}
	if len(schema.Properties["provider_trigger_allowed"]) == 0 || len(schema.Properties["enabled"]) == 0 {
		t.Fatal("native schedule lost a supported control")
	}
	var found bool
	for _, alternative := range schema.AnyOf {
		if len(alternative.Required) == 1 && alternative.Required[0] == "provider_trigger_allowed" {
			found = true
		}
	}
	if !found {
		t.Fatal("native schema cannot express a consent-only update")
	}
}
