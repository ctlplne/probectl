// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"testing"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestClientReportSDKKeepsOptionalSourceConfiguration(t *testing.T) {
	definition := sdk.DashboardDefinition{Metrics: map[string]string{"value": "1"}}
	raw, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, present := fields["client_report"]; present {
		t.Fatal("ordinary SDK dashboard acquired an implicit monthly source")
	}
	definition.ClientReport = &sdk.ClientReportDefinition{CapacityTargets: []sdk.ClientReportCapacityTarget{}}
	raw, err = json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	var native reporting.DashboardDefinition
	if err := json.Unmarshal(raw, &native); err != nil {
		t.Fatal(err)
	}
	if native.ClientReport == nil || native.ClientReport.CapacityTargets == nil || len(native.ClientReport.CapacityTargets) != 0 {
		t.Fatal("explicit monthly SDK configuration lost its typed native contract")
	}
}
