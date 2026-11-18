// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

import (
	"fmt"
	"strings"
)

// PolicyForControl limits directional PCI evidence to rules entering or
// leaving the operator's explicit cardholder data environment (CDE).
// It preserves the declared deny rules and never creates an allow rule or
// infers the identity of the CDE from traffic.
func PolicyForControl(policy Policy, control, protectedZone string) (Policy, error) {
	if usesCardholderZone(control) {
		return policyForCDEDirection(policy, protectedZone, control == PCIInboundNetworkControl)
	}
	if protectedZone != "" {
		return Policy{}, fmt.Errorf("compliance: the protected zone is only used by directional CDE controls")
	}
	return policy, nil
}

func usesCardholderZone(control string) bool {
	return control == PCIInboundNetworkControl || control == PCIOutboundNetworkControl
}

func policyForCDEDirection(policy Policy, protectedZone string, inbound bool) (Policy, error) {
	if protectedZone == "" || strings.TrimSpace(protectedZone) != protectedZone {
		return Policy{}, fmt.Errorf("compliance: select the declared cardholder-data zone")
	}
	selected := Policy{Name: policy.Name, Zones: policy.Zones, Rules: make([]Rule, 0, len(policy.Rules))}
	for _, rule := range policy.Rules {
		forward := rule.To == protectedZone
		reverse := rule.From == protectedZone
		if !inbound {
			forward, reverse = reverse, forward
		}
		if !forward {
			if !reverse || !rule.Bidirectional {
				continue
			}
			rule.From, rule.To = rule.To, rule.From
		}
		rule.Bidirectional = false
		selected.Rules = append(selected.Rules, rule)
	}
	if len(selected.Rules) == 0 {
		return Policy{}, fmt.Errorf("compliance: the declared zone has no rules in the requested direction")
	}
	return selected, nil
}
