// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package device

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestLinuxConfigPolicyChecksChronyParserOutput(t *testing.T) {
	folder := os.Getenv("PROBECTL_TEST_LINUX_CONFIG_POLICY_CAPTURES")
	const owner = "59839d0f-b29b-469d-81dc-2a6812efec1e"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	// Recorded from chronyd -p in Debian bookworm with chrony 4.3-2+deb12u3.
	for _, test := range []struct{ state, captured string }{
		{"pass", "driftfile /var/lib/chrony/drift\nserver 192.0.2.12 iburst\n"},
		{"violation", "driftfile /var/lib/chrony/drift\n"},
	} {
		body := test.captured
		if folder != "" {
			live, err := os.ReadFile(filepath.Join(folder, test.state+".conf"))
			if err != nil {
				t.Fatal(err)
			}
			body = string(live)
		}
		capture := RedactConfig(body)
		digest := hashConfig(capture)
		archive := ConfigVersion{ID: test.state, TenantID: owner, Version: 1, Content: capture, ContentHash: digest, ObservedAt: time.Now().UTC()}
		verdicts, err := EvaluateConfigPolicy(ctx, archive, []ConfigPolicyRule{
			{ID: "time-source", Revision: "1", Mode: ConfigRuleTemplate, Template: ConfigPolicyChronyNTP},
		})
		if err != nil || len(verdicts) != 1 || verdicts[0].State != test.state || verdicts[0].ArchiveSHA256 != digest {
			t.Fatal("Linux chronyd configuration produced an unexpected result", test.state, verdicts, err)
		}
	}
}
