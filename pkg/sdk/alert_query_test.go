// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSavedQueryAlertOptionalSourcePreservesLegacyAndExactThreshold(t *testing.T) {
	legacy := AlertRequest{Name: "Legacy", Metric: "probectl_probe_loss_ratio", Type: "threshold", Comparison: "gt", Threshold: 0.5}
	body, err := json.Marshal(legacy)
	if err != nil || strings.Contains(string(body), "query_source") {
		t.Fatal("SDK added an empty saved source to a legacy rule", string(body), err)
	}
	source := AlertQuerySourceInput{ViewId: "11111111-1111-4111-8111-111111111111", ViewVersion: "9007199254740993", Condition: AlertQueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: "gt", Threshold: "18446744073709551617"}}
	body, err = json.Marshal(AlertRequest{Name: "Exact query", QuerySource: &source})
	if err != nil || !strings.Contains(string(body), `"threshold":"18446744073709551617"`) || !strings.Contains(string(body), `"view_version":"9007199254740993"`) {
		t.Fatal("SDK rounded the query condition or saved revision", string(body), err)
	}
}
