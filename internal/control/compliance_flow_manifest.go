// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/reporting"
)

func portableComplianceFlowDefinition(definition *reporting.ComplianceFlowDefinition) *reporting.ComplianceFlowManifestDefinition {
	if definition == nil {
		return nil
	}
	portable := &reporting.ComplianceFlowManifestDefinition{Lookback: definition.Lookback, Slots: make([]string, len(definition.Sources))}
	for i := range definition.Sources {
		portable.Slots[i] = "point-" + strconv.Itoa(i+1)
	}
	if definition.Policy != "" {
		portable.PolicySlot = "segmentation-policy"
	}
	if definition.ProtectedZone != "" {
		portable.ProtectedZoneSlot = "cardholder-data-zone"
	}
	return portable
}

func bindComplianceFlowManifest(portable *reporting.ComplianceFlowManifestDefinition, bindings *reporting.ComplianceFlowManifestBindings) (*reporting.ComplianceFlowDefinition, error) {
	if portable == nil {
		if bindings != nil {
			return nil, apierror.Validation("compliance bindings require a flow-backed control template")
		}
		return nil, nil
	}
	if bindings == nil || len(portable.Slots) == 0 || len(portable.Slots) != len(bindings.Sources) {
		return nil, apierror.Validation("every measurement point needs one current destination binding")
	}
	if portable.PolicySlot != "" && portable.PolicySlot != "segmentation-policy" || (portable.PolicySlot == "") != (bindings.Policy == "") {
		return nil, apierror.Validation("supply the destination policy for the declared segmentation policy slot")
	}
	if portable.ProtectedZoneSlot != "" && portable.ProtectedZoneSlot != "cardholder-data-zone" ||
		(portable.ProtectedZoneSlot == "") != (bindings.ProtectedZone == "") {
		return nil, apierror.Validation("supply the destination zone for the declared cardholder-data zone slot")
	}
	definition := &reporting.ComplianceFlowDefinition{Lookback: portable.Lookback, Policy: bindings.Policy, ProtectedZone: bindings.ProtectedZone, Sources: make([]reporting.ComplianceFlowSource, 0, len(portable.Slots))}
	used := map[string]bool{}
	for _, slot := range portable.Slots {
		source, found := bindings.Sources[slot]
		if !found || used[slot] || slot == "" || strings.TrimSpace(slot) != slot {
			return nil, apierror.Validation("compliance measurement point bindings are missing or ambiguous")
		}
		definition.Sources = append(definition.Sources, source)
		used[slot] = true
	}
	return definition, nil
}
