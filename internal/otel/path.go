// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package otel

import "strconv"

// Path/traceroute attribute keys (S10 / finalized S22). The destination uses the
// OTel destination.address convention; path specifics use probectl.path.*.
const (
	AttrPathTarget   = "probectl.path.target"
	AttrPathMode     = "probectl.path.mode"
	AttrPathHopCount = "probectl.path.hop_count"
	AttrPathReached  = "probectl.path.destination_reached"
)

func init() {
	for _, k := range []string{AttrPathTarget, AttrPathMode, AttrPathHopCount, AttrPathReached} {
		KnownAttributes[k] = true
	}
}

// PathSummary is the path-signal input for OTel mapping — decoupled from
// internal/path so the conventions package depends only on the gen protos.
type PathSummary struct {
	TenantID           string
	Target             string
	TargetIP           string
	Mode               string
	HopCount           int
	DestinationReached bool
}

// pathAttributes maps a discovered path to its OTel/probectl attributes.
func pathAttributes(p PathSummary) map[string]string {
	attrs := map[string]string{
		AttrTenantID:     p.TenantID,
		AttrPathHopCount: strconv.Itoa(p.HopCount),
		AttrPathReached:  strconv.FormatBool(p.DestinationReached),
	}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	put(AttrPathTarget, p.Target)
	put(AttrDestinationAddress, p.TargetIP)
	put(AttrPathMode, p.Mode)
	return attrs
}
