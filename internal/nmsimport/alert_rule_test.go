// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/alert"
)

func TestNativeLibreNMSPortDownRuleIsDisabledAndTargetBound(t *testing.T) {
	preview := LibreNMSAlertTargetPreview{
		RuleID: "31", RuleKind: "port_down", Name: "WAN port down",
		Severity: "critical", AgentID: "collector-a", TargetAddress: "10.0.0.1",
	}
	rule, err := nativeLibreNMSPortDownRule(preview)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Enabled || rule.Metric != "probectl_device_if_oper_status" ||
		rule.Type != alert.Threshold || rule.Comparison != alert.EQ ||
		rule.Threshold != 0 || rule.ForN != 1 ||
		rule.Match["agent_id"] != "collector-a" || rule.Match["device"] != "10.0.0.1" ||
		len(rule.Match) != 2 || len(rule.Channels) != 0 || rule.Severity != alert.SeverityCritical {
		t.Fatalf("native mapping is not an exact disabled target rule: %+v", rule)
	}
	for name, change := range map[string]func(*LibreNMSAlertTargetPreview){
		"enabled source":    func(p *LibreNMSAlertTargetPreview) { p.Enabled = true },
		"unknown rule kind": func(p *LibreNMSAlertTargetPreview) { p.RuleKind = "arbitrary_sql" },
		"unknown severity":  func(p *LibreNMSAlertTargetPreview) { p.Severity = "ok" },
		"invalid source ID": func(p *LibreNMSAlertTargetPreview) { p.RuleID = "31 OR 1=1" },
		"oversized name":    func(p *LibreNMSAlertTargetPreview) { p.Name = strings.Repeat("x", 201) },
		"missing agent":     func(p *LibreNMSAlertTargetPreview) { p.AgentID = "" },
		"missing target":    func(p *LibreNMSAlertTargetPreview) { p.TargetAddress = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := preview
			change(&candidate)
			if _, err := nativeLibreNMSPortDownRule(candidate); err == nil {
				t.Fatal("invalid imported alert accepted")
			}
		})
	}
}
