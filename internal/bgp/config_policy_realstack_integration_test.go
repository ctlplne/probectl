// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestFRRConfigPolicyChecksOriginalRunningConfigs(t *testing.T) {
	lab := startRoutingLab(t)
	lab.docker(t, "exec", lab.container("rtr-a"), "vtysh", "-c", "configure terminal",
		"-c", "log syslog informational", "-c", "end")
	lab.docker(t, "exec", lab.container("rtr-b"), "vtysh", "-c", "configure terminal",
		"-c", "no log syslog", "-c", "no log file", "-c", "end")
	rules := []device.ConfigPolicyRule{{ID: "frr-logging", Revision: "1", Mode: device.ConfigRuleTemplate, Template: device.ConfigPolicyFRRLogging}}
	for _, lane := range []struct{ router, tenant, expected string }{
		{"rtr-a", "0acdcddd-5550-4a7f-9ca3-0bdf794e48ee", "pass"},
		{"rtr-b", "71b1d4c5-3b89-4364-bfef-da0ec604c0de", "violation"},
	} {
		capture := device.RedactConfig(lab.docker(t, "exec", lab.container(lane.router), "vtysh", "-c", "show running-config"))
		digest := hex.EncodeToString(crypto.Hash([]byte(capture)))
		archive := device.ConfigVersion{ID: lane.router, TenantID: lane.tenant, Version: 1,
			Content: capture, ContentHash: digest, ObservedAt: time.Now().UTC()}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenant))
		got, err := device.EvaluateConfigPolicy(ctx, archive, rules)
		if err != nil || len(got) != 1 || got[0].State != lane.expected || got[0].ArchiveSHA256 != digest {
			t.Fatal("the FRRouting capture did not produce its original policy verdict", lane.router, got, err)
		}
	}
	t.Log("real-integration: both pinned FRRouting routers supplied original running configurations for their respective logging verdicts")
}
