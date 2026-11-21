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
	if folder == "" {
		t.Skip("set the directory containing pass.conf and violation.conf from the owned chronyd parser")
	}
	const owner = "59839d0f-b29b-469d-81dc-2a6812efec1e"
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(owner))
	for _, state := range []string{"pass", "violation"} {
		body, err := os.ReadFile(filepath.Join(folder, state+".conf"))
		if err != nil {
			t.Fatal(err)
		}
		capture := RedactConfig(string(body))
		digest := hashConfig(capture)
		archive := ConfigVersion{ID: state, TenantID: owner, Version: 1, Content: capture, ContentHash: digest, ObservedAt: time.Now().UTC()}
		verdicts, err := EvaluateConfigPolicy(ctx, archive, []ConfigPolicyRule{
			{ID: "time-source", Revision: "1", Mode: ConfigRuleTemplate, Template: ConfigPolicyChronyNTP},
		})
		if err != nil || len(verdicts) != 1 || verdicts[0].State != state || verdicts[0].ArchiveSHA256 != digest {
			t.Fatal("Linux chronyd configuration produced an unexpected result", state, verdicts, err)
		}
	}
}
