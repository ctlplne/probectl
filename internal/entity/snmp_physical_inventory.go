// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"cmp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	SNMPPhysicalInventorySource = "snmp:physical-inventory"
	MaxSNMPPhysicalComponents   = 512
	maxSNMPPhysicalIndex        = 1<<31 - 1
)

// SNMPPhysicalInventory is optional evidence from the authenticated device
// target. A present but unavailable snapshot records a failed or unsupported
// walk without replacing any previously retained original component values.
type SNMPPhysicalInventory struct {
	Version    uint32                  `json:"version"`
	Available  bool                    `json:"available"`
	Components []SNMPPhysicalComponent `json:"components,omitempty"`
}

// SNMPPhysicalComponent contains only original ENTITY-MIB leaves. The index
// identifies the row within this device and cannot select a tenant or entity.
type SNMPPhysicalComponent struct {
	Index        uint32  `json:"index"`
	Class        uint32  `json:"class"`
	Parent       *uint32 `json:"parent,omitempty"`
	Manufacturer string  `json:"manufacturer,omitempty"`
	Model        string  `json:"model,omitempty"`
	Serial       string  `json:"serial,omitempty"`
	Hardware     string  `json:"hardware,omitempty"`
	Firmware     string  `json:"firmware,omitempty"`
	Software     string  `json:"software,omitempty"`
}

func NormalizeSNMPPhysicalInventory(snapshot *SNMPPhysicalInventory) (*SNMPPhysicalInventory, error) {
	if snapshot == nil {
		return nil, nil
	}
	rows := snapshot.Components
	if snapshot.Version != 1 || snapshot.Available != (len(rows) != 0) || len(rows) > MaxSNMPPhysicalComponents {
		return nil, ErrInvalidClaim
	}
	result := &SNMPPhysicalInventory{Version: 1, Available: snapshot.Available, Components: slices.Clone(rows)}
	for i := range result.Components {
		row := &result.Components[i]
		if row.Index == 0 || row.Index > maxSNMPPhysicalIndex || row.Class < 1 || row.Class > 14 ||
			!validSNMPPhysicalText(row.Serial, 32) || !validSNMPPhysicalText(row.Manufacturer, 255) ||
			!validSNMPPhysicalText(row.Model, 255) || !validSNMPPhysicalText(row.Hardware, 255) ||
			!validSNMPPhysicalText(row.Firmware, 255) || !validSNMPPhysicalText(row.Software, 255) {
			return nil, ErrInvalidClaim
		}
		if row.Parent != nil {
			parent := *row.Parent
			if parent > maxSNMPPhysicalIndex || parent == row.Index {
				return nil, ErrInvalidClaim
			}
			row.Parent = &parent
		}
	}
	slices.SortFunc(result.Components, func(left, right SNMPPhysicalComponent) int {
		return cmp.Compare(left.Index, right.Index)
	})
	for i := 1; i < len(result.Components); i++ {
		if result.Components[i].Index == result.Components[i-1].Index {
			return nil, ErrInvalidClaim
		}
	}
	return result, nil
}

func normalizePhysicalInventoryObservation(o Observation) (*SNMPPhysicalInventory, error) {
	if o.SNMPPhysicalInventory == nil && o.SourceRef != SNMPPhysicalInventorySource {
		return nil, nil
	}
	if o.Source.Kind != DeviceTarget || o.Alias.Kind != AddressAlias ||
		o.SourceRef != SNMPPhysicalInventorySource || o.SNMPPhysicalInventory == nil {
		return nil, ErrInvalidClaim
	}
	return NormalizeSNMPPhysicalInventory(o.SNMPPhysicalInventory)
}

func validSNMPPhysicalText(value string, maximum int) bool {
	return len(value) <= maximum && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(character rune) bool { return !unicode.IsPrint(character) }) == -1
}
