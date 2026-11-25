// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"net"
	"net/netip"
	"regexp"
)

// ICMPEgressWitness is a collector's local first-hop observation. Use it only
// after independently matching the current tenant's assigned agent, test,
// routing context and handoff. A sender cannot name an upstream by assertion.
type ICMPEgressWitness struct {
	Interface   string `json:"interface"`
	Source      string `json:"source"`
	PeerMAC     string `json:"peer_mac"`
	Transmitted uint32 `json:"transmitted"`
}

var icmpEgressInterfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// ValidICMPEgressInterface identifies supported Linux Ethernet interface names.
func ValidICMPEgressInterface(value string) bool {
	return value != "." && value != ".." && icmpEgressInterfaceName.MatchString(value)
}

func normalizeICMPEgress(m ICMPMeasurement, target netip.Addr) (*ICMPEgressWitness, error) {
	if m.Version != ICMPVersionEgress {
		if m.Egress != nil {
			return nil, ErrInvalidClaim
		}
		return nil, nil
	}
	if m.Egress == nil || m.Requested > MaxICMPEgressAttempts || m.Transmitted != m.Requested ||
		m.Egress.Transmitted != m.Transmitted || !m.ReadComplete || m.Canceled || m.IOFailed ||
		!m.Egress.ValidCoordinates(target) {
		return nil, ErrInvalidClaim
	}
	witness := *m.Egress
	return &witness, nil
}

// ValidCoordinates checks the same canonical link identity in an operator
// binding or a probe observation. It establishes shape only.
func (w ICMPEgressWitness) ValidCoordinates(target netip.Addr) bool {
	if !ValidICMPEgressInterface(w.Interface) || !target.IsGlobalUnicast() || target.Zone() != "" || target.Is4In6() {
		return false
	}
	source, err := netip.ParseAddr(w.Source)
	if err != nil || source.String() != w.Source || source.Zone() != "" || source.Is4In6() ||
		!source.IsGlobalUnicast() || source == target || source.Is4() != target.Is4() {
		return false
	}
	mac, err := net.ParseMAC(w.PeerMAC)
	return err == nil && len(mac) == 6 && mac.String() == w.PeerMAC && mac[0]&1 == 0 &&
		w.PeerMAC != "00:00:00:00:00:00"
}

// SameCoordinates compares the interface, source and first hop without the
// execution's packet population.
func (w ICMPEgressWitness) SameCoordinates(other ICMPEgressWitness) bool {
	return w.Interface == other.Interface && w.Source == other.Source && w.PeerMAC == other.PeerMAC
}
