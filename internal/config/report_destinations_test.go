// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "testing"

func TestReportEmailDestinationsKeepTenantRoutingAndFailClosed(t *testing.T) {
	const key = "PROBECTL_REPORT_EMAIL_DESTINATIONS"
	valid := `[{"tenant_id":"11111111-1111-4111-8111-111111111111","id":"monthly","name":"Client accounting","recipients":["accounting@example.test"]},{"tenant_id":"22222222-2222-4222-8222-222222222222","id":"monthly","name":"Other client","recipients":["other@example.test"]}]`
	cfg, err := Load(envFunc(map[string]string{key: valid}))
	if err != nil || len(cfg.ReportEmailDestinations) != 2 || cfg.ReportEmailDestinations[0].Recipients[0] == cfg.ReportEmailDestinations[1].Recipients[0] {
		t.Fatal("configured email routes lost tenant identity", err)
	}
	for _, raw := range []string{
		`[{"tenant_id":"not-a-tenant","id":"x","name":"x","recipients":["client@example.test"]}]`,
		`[{"tenant_id":"11111111-1111-4111-8111-111111111111","id":"x","name":"x","recipients":["Client <client@example.test>"]}]`,
		`[{"tenant_id":"11111111-1111-4111-8111-111111111111","id":"x","name":"x","recipients":["client@example.test"],"untrusted":true}]`,
		valid + ` {}`,
	} {
		if _, err := Load(envFunc(map[string]string{key: raw})); err == nil {
			t.Fatal("invalid report destination accepted")
		}
	}
}
