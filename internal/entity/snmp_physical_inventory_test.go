// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSNMPPhysicalInventoryPreservesPresenceAndSource(t *testing.T) {
	parent := uint32(0)
	now := time.Now().UTC()
	claim := Observation{ID: "66666666-6666-4666-8666-666666666666",
		Source: SourceKey{AgentID: "device-collector", Kind: DeviceTarget, SourceRef: "192.0.2.12"},
		Alias:  AliasKey{Kind: AddressAlias, Value: "192.0.2.12"}, SourceRef: SNMPPhysicalInventorySource,
		ObservedAt: now, SNMPPhysicalInventory: &SNMPPhysicalInventory{Version: 1, Available: true,
			Components: []SNMPPhysicalComponent{{Index: 12, Class: 9, Model: "module"}, {Index: 3, Class: 3, Parent: &parent}}},
	}
	normalized, err := claim.Normalize(now)
	if err != nil || normalized.SNMPPhysicalInventory.Components[0].Index != 3 ||
		normalized.SNMPPhysicalInventory.Components[0].Parent == nil ||
		*normalized.SNMPPhysicalInventory.Components[0].Parent != 0 ||
		normalized.SNMPPhysicalInventory.Components[1].Parent != nil {
		t.Fatal("component order or original parent presence was lost", err)
	}
	parent = 4
	if *normalized.SNMPPhysicalInventory.Components[0].Parent != 0 {
		t.Fatal("the normalized observation borrowed mutable input")
	}
	for _, field := range []struct {
		name   string
		mutate func(*Observation)
	}{
		{"ordinary observation", func(o *Observation) { o.SourceRef = "snmp:configured-target" }},
		{"unavailable rows", func(o *Observation) { o.SNMPPhysicalInventory.Available = false }},
		{"duplicate index", func(o *Observation) { o.SNMPPhysicalInventory.Components[1].Index = 12 }},
		{"invalid firmware", func(o *Observation) { o.SNMPPhysicalInventory.Components[0].Firmware = strings.Repeat("x", 256) }},
		{"missing typed payload", func(o *Observation) { o.SNMPPhysicalInventory = nil }},
	} {
		t.Run(field.name, func(t *testing.T) {
			candidate := claim
			inventory := *claim.SNMPPhysicalInventory
			inventory.Components = append([]SNMPPhysicalComponent(nil), inventory.Components...)
			candidate.SNMPPhysicalInventory = &inventory
			field.mutate(&candidate)
			if _, err := candidate.Normalize(now); !errors.Is(err, ErrInvalidClaim) {
				t.Fatal("invalid inventory evidence was admitted", err)
			}
		})
	}
	claim.SNMPPhysicalInventory = &SNMPPhysicalInventory{Version: 1}
	if got, err := claim.Normalize(now); err != nil || got.SNMPPhysicalInventory == nil || got.SNMPPhysicalInventory.Available {
		t.Fatal("an unavailable observation lost its explicit presence", err)
	}
}
