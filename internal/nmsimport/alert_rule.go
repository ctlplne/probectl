// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import "github.com/ctlplne/probectl/internal/alert"

// nativeLibreNMSPortDownRule is the sole destination shape admitted by the
// finite source classifier. The caller must recheck the tenant/context/source
// provenance and the current operator-owned agent target in the write
// transaction before creating it. Neither the source SQL nor its delivery
// operations enter this rule (docs/guardrails.md G7-1, G7-8, G7-12).
func nativeLibreNMSPortDownRule(p LibreNMSAlertTargetPreview) (alert.Rule, error) {
	if p.RuleKind != "port_down" || p.Enabled || !canonicalSourceNumber(p.RuleID) ||
		p.Name == "" || len(p.Name) > 200 || safeLabel(p.Name) != p.Name ||
		p.AgentID == "" || len(p.AgentID) > 128 || safeLabel(p.AgentID) != p.AgentID ||
		p.TargetAddress == "" || len(p.TargetAddress) > 255 ||
		safeLabel(p.TargetAddress) != p.TargetAddress ||
		(p.Severity != "warning" && p.Severity != "critical") {
		return alert.Rule{}, ErrInvalidReview
	}
	rule := alert.Rule{
		Name:       p.Name,
		Enabled:    false,
		Metric:     "probectl_device_if_oper_status",
		Match:      map[string]string{"agent_id": p.AgentID, "device": p.TargetAddress},
		Type:       alert.Threshold,
		Comparison: alert.EQ,
		Threshold:  0,
		ForN:       1,
		Severity:   alert.Severity(p.Severity),
		Channels:   []alert.ChannelSpec{},
	}
	if err := rule.Validate(); err != nil {
		return alert.Rule{}, ErrInvalidReview
	}
	return rule, nil
}
