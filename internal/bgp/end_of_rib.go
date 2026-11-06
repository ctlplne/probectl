// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"encoding/binary"
	"errors"
)

// RouteFamily is an explicit source AFI/SAFI tuple. A marker for one family
// cannot complete another family's view, or authorize a source/session epoch.
type RouteFamily struct {
	AFI  uint16
	SAFI uint8
}

var ErrBGPRouteFrame = errors.New("bgp: malformed route marker frame")

// ParseBGPEndOfRIB recognizes only RFC4724 markers in a complete BGP frame.
// This is not a validator for other UPDATE contents or a current-RIB proof.
// The authenticated source, negotiated family/view, initial generation and
// current credential clocks still have to be established before publication.
func ParseBGPEndOfRIB(raw []byte) (RouteFamily, bool, error) {
	none := RouteFamily{}
	if len(raw) < bgpHeaderLen {
		return none, false, ErrBGPRouteFrame
	}
	for _, b := range raw[:16] {
		if b != 255 {
			return none, false, ErrBGPRouteFrame
		}
	}
	if int(binary.BigEndian.Uint16(raw[16:18])) != len(raw) {
		return none, false, ErrBGPRouteFrame
	}
	if raw[18] != 2 {
		return none, false, nil
	}
	if len(raw) < bgpHeaderLen+4 {
		return none, false, ErrBGPRouteFrame
	}
	withdrawn := int(binary.BigEndian.Uint16(raw[19:21]))
	if withdrawn > len(raw)-bgpHeaderLen-4 {
		return none, false, ErrBGPRouteFrame
	}
	offset := bgpHeaderLen + 2 + withdrawn
	length := int(binary.BigEndian.Uint16(raw[offset : offset+2]))
	offset += 2
	if length > len(raw)-offset {
		return none, false, ErrBGPRouteFrame
	}
	bodyEnd := offset + length
	// Reachable routes, even a default route, cannot be mistaken for an
	// empty synchronization marker. Withdrawals also disqualify the marker.
	if bodyEnd != len(raw) || withdrawn != 0 {
		return none, false, nil
	}
	if length == 0 {
		return RouteFamily{AFI: 1, SAFI: 1}, true, nil
	}
	attributes := raw[offset:bodyEnd]
	if len(attributes) < 3 {
		return none, false, ErrBGPRouteFrame
	}
	flags, kind := attributes[0], attributes[1]
	headerLength, valueLength := 3, int(attributes[2])
	if flags&0x10 != 0 {
		if len(attributes) < 4 {
			return none, false, ErrBGPRouteFrame
		}
		headerLength, valueLength = 4, int(binary.BigEndian.Uint16(attributes[2:4]))
	}
	if valueLength > len(attributes)-headerLength {
		return none, false, ErrBGPRouteFrame
	}
	// Any additional attribute means this is not the RFC4724 marker. Do
	// not search for an empty MP_UNREACH inside a route-carrying UPDATE.
	if headerLength+valueLength != len(attributes) || kind != 15 {
		return none, false, nil
	}
	if flags&0xe0 != 0x80 || valueLength < 3 {
		return none, false, ErrBGPRouteFrame
	}
	if valueLength != 3 {
		return none, false, nil
	}
	value := attributes[headerLength:]
	return RouteFamily{AFI: binary.BigEndian.Uint16(value[:2]), SAFI: value[2]}, true, nil
}
