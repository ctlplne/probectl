// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strconv"

	"github.com/ctlplne/probectl/internal/crypto"
)

// BMPPeerSession is an original global physical-neighbor lifecycle fact.
// Source identity, context and interface ownership must still be resolved by
// tenant storage. Session loss alone never attributes a carrier failure.
type BMPPeerSession struct {
	RawFrame            []byte  `json:"raw_frame"`
	Version             int     `json:"version"`
	State               string  `json:"state"` // up | down | monitoring_withdrawn
	PeerAddress         string  `json:"peer_address"`
	PeerASN             uint32  `json:"peer_asn"`
	Flags               uint32  `json:"flags"`
	DownReason          *uint32 `json:"down_reason,omitempty"`
	FSMEvent            *uint32 `json:"fsm_event,omitempty"`
	NotificationCode    *uint32 `json:"notification_code,omitempty"`
	NotificationSubcode *uint32 `json:"notification_subcode,omitempty"`
	FrameDigest         string  `json:"frame_digest"`
}

// Validate checks the complete typed shape, without creating a source grant.
func (m BMPPeerSession) Validate() error {
	address, err := netip.ParseAddr(m.PeerAddress)
	if err != nil || address.Zone() != "" || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Unmap().String() != m.PeerAddress || m.Version != 1 || m.PeerASN == 0 || m.Flags&^uint32(0xf0) != 0 {
		return ErrInvalidClaim
	}
	digest, err := hex.DecodeString(m.FrameDigest)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != m.FrameDigest || len(m.RawFrame) == 0 || !bytes.Equal(digest, crypto.Hash(m.RawFrame)) {
		return ErrInvalidClaim
	}
	if m.State == "up" {
		if m.DownReason != nil || m.FSMEvent != nil || m.NotificationCode != nil || m.NotificationSubcode != nil {
			return ErrInvalidClaim
		}
		return nil
	}
	if m.DownReason == nil || *m.DownReason < 1 || *m.DownReason > 6 || m.State != "down" && m.State != "monitoring_withdrawn" {
		return ErrInvalidClaim
	}
	if (m.State == "monitoring_withdrawn") != (*m.DownReason == 5) {
		return ErrInvalidClaim
	}
	notification := *m.DownReason == 1 || *m.DownReason == 3
	if notification != (m.NotificationCode != nil && m.NotificationSubcode != nil) || (m.NotificationCode == nil) != (m.NotificationSubcode == nil) {
		return ErrInvalidClaim
	}
	if m.NotificationCode != nil && (*m.NotificationCode > 255 || *m.NotificationSubcode > 255) {
		return ErrInvalidClaim
	}
	if m.FSMEvent != nil && (*m.DownReason != 2 || *m.FSMEvent == 0 || *m.FSMEvent > 65535) {
		return ErrInvalidClaim
	}
	return nil
}

func normalizeBMPPeerSession(o Observation) (*BMPPeerSession, error) {
	if o.BMPPeerSession == nil {
		return nil, nil
	}
	m := o.BMPPeerSession
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if o.Source.Kind != BMPPeer || o.Alias.Kind != BMPPeerAlias || o.Alias.Value != m.PeerAddress+"/as"+strconv.FormatUint(uint64(m.PeerASN), 10) || o.ICMP != nil || o.Outcome != nil || o.SNMPInterfaceState != nil {
		return nil, ErrInvalidClaim
	}
	out := *m
	out.RawFrame = append([]byte(nil), m.RawFrame...)
	for _, field := range []**uint32{&out.DownReason, &out.FSMEvent, &out.NotificationCode, &out.NotificationSubcode} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	return &out, nil
}
