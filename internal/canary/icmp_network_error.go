// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/ctlplne/probectl/internal/crypto"
)

// ICMPNetworkError is one collector-local, challenge-matched probe outcome.
// It does not select a tenant, source, routing context, ASN or fault domain.
// Conflicting terminal outcomes remain explicit rather than selecting a winner.
type ICMPNetworkError struct {
	Sequence     uint32
	Responder    string
	Type, Code   uint32
	ReceivedAt   time.Time
	PacketDigest [32]byte
	Conflicting  bool
}

// A minimum RFC quote may omit the challenge; that is unavailable evidence.
// Echo IDs/16-bit sequences alone cannot authenticate a quoted probe, including
// when the configured population crosses the wire sequence-number wrap.
func quotedICMPEcho(v6 bool, quote []byte) (*icmp.Echo, netip.Addr, bool) {
	offset, total, protocol := 0, 0, ianaProtoICMP
	var target netip.Addr
	if v6 {
		if len(quote) < 40 || quote[0]>>4 != 6 {
			return nil, target, false
		}
		total = 40 + int(binary.BigEndian.Uint16(quote[4:6]))
		var address [16]byte
		copy(address[:], quote[24:40])
		target = netip.AddrFrom16(address)
		var ok bool
		offset, ok = quotedIPv6ICMPOffset(quote, total)
		if !ok {
			return nil, target, false
		}
		protocol = ianaProtoICMPv6
	} else {
		if len(quote) < 20 || quote[0]>>4 != 4 || quote[9] != ianaProtoICMP || binary.BigEndian.Uint16(quote[6:8])&0x1fff != 0 {
			return nil, target, false
		}
		offset = int(quote[0]&15) * 4
		total = int(binary.BigEndian.Uint16(quote[2:4]))
		target = netip.AddrFrom4([4]byte(quote[16:20]))
		if offset < 20 {
			return nil, target, false
		}
	}
	end := min(total, len(quote))
	if offset+16 > end {
		return nil, target, false
	}
	message, err := icmp.ParseMessage(protocol, quote[offset:end])
	if err != nil || message.Code != 0 {
		return nil, target, false
	}
	if v6 && message.Type != ipv6.ICMPTypeEchoRequest || !v6 && message.Type != ipv4.ICMPTypeEcho {
		return nil, target, false
	}
	echo, ok := message.Body.(*icmp.Echo)
	return echo, target.Unmap(), ok && len(echo.Data) >= 8
}

func quotedIPv6ICMPOffset(quote []byte, total int) (int, bool) {
	offset, next := 40, quote[6]
	end := min(total, len(quote))
	for next != ianaProtoICMPv6 {
		if offset+8 > end {
			return 0, false
		}
		length := 0
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing and Destination Options.
			length = (int(quote[offset+1]) + 1) * 8
		case 51: // Authentication Header.
			length = (int(quote[offset+1]) + 2) * 4
		case 44:
			if binary.BigEndian.Uint16(quote[offset+2:offset+4])&0xfff8 != 0 {
				return 0, false
			}
			length = 8
		default:
			return 0, false
		}
		if length < 8 || length > end-offset {
			return 0, false
		}
		next = quote[offset]
		offset += length
	}
	return offset, offset+16 <= end
}

// Only a complete quote carrying this run's random challenge can supply a
// terminal network-error fact. Unrelated errors remain ordinary receive work.
func (s *icmpProbeState) retainNetworkError(message *icmp.Message, packet []byte, peer net.Addr, receivedAt time.Time) bool {
	if s.v6 && message.Type != ipv6.ICMPTypeDestinationUnreachable || !s.v6 && message.Type != ipv4.ICMPTypeDestinationUnreachable {
		return false
	}
	body, ok := message.Body.(*icmp.DstUnreach)
	if !ok {
		return true
	}
	echo, target, ok := quotedICMPEcho(s.v6, body.Data)
	if !ok || target != s.target || len(echo.Data) > len(s.payload) || !bytes.Equal(echo.Data[8:], s.payload[8:len(echo.Data)]) || s.raw && echo.ID != s.id {
		return true
	}
	sequence, known := s.challenges[binary.BigEndian.Uint64(echo.Data[:8])]
	if !known || echo.Seq != sequence&0xffff {
		return true
	}
	responder, ok := icmpResponder(peer)
	if !ok || !icmpNetworkErrorChecksum(s.v6, packet, body.Data, responder) {
		return true
	}
	var digest [32]byte
	copy(digest[:], crypto.Hash(packet))
	fact := ICMPNetworkError{Sequence: uint32(sequence), Responder: responder, Code: uint32(message.Code), ReceivedAt: receivedAt.UTC(), PacketDigest: digest}
	if s.v6 {
		fact.Type = uint32(ipv6.ICMPTypeDestinationUnreachable)
	} else {
		fact.Type = uint32(ipv4.ICMPTypeDestinationUnreachable)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sequence < 0 || sequence >= len(s.written) || sequence >= len(s.networkErrors) || !s.written[sequence] {
		return true
	}
	if old := s.networkErrors[sequence]; old != nil {
		if old.Responder != fact.Responder || old.Type != fact.Type || old.Code != fact.Code {
			old.Conflicting = true
		}
		return true
	}
	s.networkErrors[sequence] = &fact
	return true
}

// Internet checksums validate protocol framing; cryptographic evidence digests
// above still use the single internal/crypto door.
func icmpNetworkErrorChecksum(v6 bool, packet, quote []byte, responder string) bool {
	sum := icmpNetworkWordSum(packet)
	if v6 {
		source, err := netip.ParseAddr(responder)
		if err != nil || !source.Is6() || source.Is4In6() || len(quote) < 40 {
			return false
		}
		ip := source.As16()
		sum += icmpNetworkWordSum(ip[:]) + icmpNetworkWordSum(quote[8:24]) + uint32(len(packet)>>16) + uint32(len(packet)&0xffff) + ianaProtoICMPv6
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}
func icmpNetworkWordSum(packet []byte) uint32 {
	var sum uint32
	for len(packet) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[:2]))
		packet = packet[2:]
	}
	if len(packet) > 0 {
		sum += uint32(packet[0]) << 8
	}
	return sum
}
