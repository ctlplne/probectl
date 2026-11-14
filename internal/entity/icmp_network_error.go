// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"encoding/hex"
	"net/netip"
	"slices"
	"time"
)

// MaxICMPMeasurementWireBytes admits the complete 100000-probe configured
// population, including IPv6 responders, under finite transport admission.
const MaxICMPMeasurementWireBytes = 16 << 20

// ICMPNetworkError retains an original challenge-matched collector outcome.
// An address is observed packet provenance, never a tenant, ASN or identity
// grant. Competing outcomes explicitly remain unavailable for attribution.
type ICMPNetworkError struct {
	Sequence     uint32    `json:"sequence"`
	Responder    string    `json:"responder"`
	Type         uint32    `json:"type"`
	Code         uint32    `json:"code"`
	ReceivedAt   time.Time `json:"received_at"`
	PacketDigest string    `json:"packet_digest"`
	Conflicting  bool      `json:"conflicting"`
}

func normalizeICMPNetworkErrors(m ICMPMeasurement, target netip.Addr) ([]ICMPNetworkError, error) {
	if m.Version == 1 {
		if len(m.NetworkErrors) != 0 {
			return nil, ErrInvalidClaim
		}
		return nil, nil
	}
	if m.Version == 3 && len(m.NetworkErrors) == 0 {
		return nil, nil
	}
	if (m.Version != 2 && m.Version != 3) || len(m.NetworkErrors) == 0 || uint64(len(m.NetworkErrors)) > uint64(m.Transmitted) {
		return nil, ErrInvalidClaim
	}
	out := append([]ICMPNetworkError(nil), m.NetworkErrors...)
	seen := map[uint32]bool{}
	for i := range out {
		item := &out[i]
		address, err := netip.ParseAddr(item.Responder)
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.Unmap().String() != item.Responder || address.Unmap().Is4() != target.Unmap().Is4() || item.Sequence >= m.Requested || seen[item.Sequence] || item.Code > 255 {
			return nil, ErrInvalidClaim
		}
		if target.Is4() && item.Type != 3 || target.Is6() && item.Type != 1 {
			return nil, ErrInvalidClaim
		}
		digest, err := hex.DecodeString(item.PacketDigest)
		if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != item.PacketDigest || item.PacketDigest == "0000000000000000000000000000000000000000000000000000000000000000" {
			return nil, ErrInvalidClaim
		}
		item.ReceivedAt = item.ReceivedAt.UTC()
		if m.Version < 3 {
			item.ReceivedAt = item.ReceivedAt.Truncate(time.Microsecond)
		}
		if item.ReceivedAt.Before(m.StartedAt) || item.ReceivedAt.After(m.CompletedAt) {
			return nil, ErrInvalidClaim
		}
		seen[item.Sequence] = true
	}
	slices.SortFunc(out, func(a, b ICMPNetworkError) int {
		if a.Sequence < b.Sequence {
			return -1
		}
		if a.Sequence > b.Sequence {
			return 1
		}
		return 0
	})
	return out, nil
}
