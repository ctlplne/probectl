// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ICMPMeasurement records completed collector IO, not identity or notification
// authority. The agent's evidence transport must bind these facts to its live
// identity, current test/configuration and tenant before a source can use them.
// It is not accepted from or serialized onto the ordinary result bus.
type ICMPMeasurement struct {
	TargetIP                                              string
	StartedAt, CompletedAt                                time.Time
	Expected, Attempted, Transmitted, Replies, SendErrors int
	ReadComplete, Canceled, IOFailed                      bool
	Responders                                            []string
}

func (m ICMPMeasurement) Complete() bool {
	_, err := netip.ParseAddr(m.TargetIP)
	return err == nil && !m.StartedAt.IsZero() && !m.CompletedAt.Before(m.StartedAt) &&
		m.Expected > 0 && m.Attempted == m.Expected && m.Transmitted == m.Expected &&
		m.Replies >= 0 && m.Replies <= m.Transmitted && m.SendErrors == 0 &&
		m.ReadComplete && !m.Canceled && !m.IOFailed && (m.Replies == 0 || len(m.Responders) > 0)
}

type icmpProbeConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	Close() error
}

type icmpProbeState struct {
	mu            sync.Mutex
	rtts, offsets []time.Duration
	sentAt        []time.Time
	written       []bool
	payload       []byte
	challenges    map[uint64]int
	id            int
	raw, v6       bool
	readFailed    bool
	responders    map[string]bool
}

func (s *icmpProbeState) read(ctx context.Context, conn icmpProbeConn, deadline time.Time) {
	protocol := ianaProtoICMP
	if s.v6 {
		protocol = ianaProtoICMPv6
	}
	// One sentinel byte detects oversized replies; complete configured payloads
	// above the old Ethernet-sized buffer remain supported.
	bufferBytes := 8 + len(s.payload) + 1
	if s.raw && !s.v6 {
		// Linux net.IPConn reads the outer IPv4 header into this same
		// buffer before stripping it. Reserve the protocol's maximum IHL
		// (15 four-byte words), so a valid echo is not truncated first.
		bufferBytes += 15 * 4
	}
	buffer := make([]byte, bufferBytes)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				s.readFailed = true
			}
			return
		}
		if n > 8+len(s.payload) {
			continue
		}
		receivedAt := time.Now()
		message, err := icmp.ParseMessage(protocol, buffer[:n])
		if err != nil || message.Code != 0 {
			continue
		}
		if s.v6 && message.Type != ipv6.ICMPTypeEchoReply || !s.v6 && message.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := message.Body.(*icmp.Echo)
		if !ok || len(echo.Data) != len(s.payload) || len(echo.Data) < 8 || !bytes.Equal(echo.Data[8:], s.payload[8:]) || s.raw && echo.ID != s.id {
			continue
		}
		sequence, known := s.challenges[binary.BigEndian.Uint64(echo.Data[:8])]
		if !known || echo.Seq != sequence&0xffff {
			continue
		}
		s.mu.Lock()
		if s.written[sequence] && s.rtts[sequence] < 0 {
			s.rtts[sequence] = receivedAt.Sub(s.sentAt[sequence])
			if address, ok := icmpResponder(peer); ok {
				s.responders[address] = true
			} else {
				s.readFailed = true
			}
		}
		s.mu.Unlock()
	}
}

func icmpResponder(peer net.Addr) (string, bool) {
	var ip net.IP
	switch value := peer.(type) {
	case *net.IPAddr:
		if value != nil {
			ip = value.IP
		}
	case *net.UDPAddr:
		if value != nil {
			ip = value.IP
		}
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok || address.IsUnspecified() || address.IsMulticast() {
		return "", false
	}
	return address.Unmap().String(), true
}

func (s *icmpProbeState) received() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, duration := range s.rtts {
		if duration >= 0 {
			count++
		}
	}
	return count
}

func (s *icmpProbeState) finish(ctx context.Context, facts ICMPMeasurement, deadline time.Time) ICMPMeasurement {
	facts.CompletedAt = time.Now().UTC()
	facts.Replies = s.received()
	facts.Canceled = ctx.Err() != nil
	facts.IOFailed = facts.IOFailed || s.readFailed
	facts.ReadComplete = facts.Replies == facts.Expected || !time.Now().Before(deadline)
	for address := range s.responders {
		facts.Responders = append(facts.Responders, address)
	}
	sort.Strings(facts.Responders)
	return facts
}

func (c *icmpCanary) measurementResult(res Result, rtts, offsets []time.Duration, facts ICMPMeasurement) Result {
	res.ICMP = &facts
	stats := computeLatencyStats(rtts, facts.Transmitted)
	res.Metrics = stats.latencyMetrics("rtt")
	res.Metrics["packets.requested"] = float64(facts.Expected)
	res.Metrics["packets.attempted"] = float64(facts.Attempted)
	res.Metrics["packets.send_errors"] = float64(facts.SendErrors)
	if facts.Complete() {
		res.Metrics["measurement.complete"] = 1
	} else {
		res.Metrics["measurement.complete"] = 0
	}
	if facts.Transmitted == 0 {
		delete(res.Metrics, "loss.ratio")
	}
	// Unsent requests are local IO failures, not packets lost on the network.
	drops := append([]time.Duration(nil), rtts...)
	for i := range drops {
		if offsets[i] < 0 {
			drops[i] = 0
		}
	}
	if seqs, sends := dropRecord(drops, offsets); seqs != "" {
		res.Attributes["probectl.icmp.dropped_seqs"] = seqs
		res.Attributes["probectl.icmp.drop_send_offsets_ms"] = sends
	}
	res.Success = facts.Replies > 0
	if !res.Success {
		switch {
		case facts.Canceled:
			res.Error = "ICMP measurement canceled"
		case facts.Transmitted == 0:
			res.Error = "no ICMP request was transmitted"
		case !facts.Complete():
			res.Error = "ICMP measurement incomplete because of local IO"
		default:
			res.Error = "100% packet loss"
		}
	}
	return res
}

// The x/net IP wrappers expose the underlying net.PacketConn. Resize that
// socket before probing; a fixed small kernel queue can otherwise drop a
// three-packet large-payload batch even on loopback. Do not change host sysctls.
func (c *icmpCanary) setReadBuffer(conn *icmp.PacketConn, v6 bool) error {
	var underlying net.PacketConn
	if v6 {
		if packet := conn.IPv6PacketConn(); packet != nil {
			underlying = packet.PacketConn
		}
	} else if packet := conn.IPv4PacketConn(); packet != nil {
		underlying = packet.PacketConn
	}
	buffered, ok := underlying.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("ICMP receive buffer is unavailable")
	}
	return buffered.SetReadBuffer(c.readBuffer)
}

// ICMPRequestedPackets returns the actual compiled-in ICMP profile population,
// including continuous-mode defaults. Zero means a different canary type.
func ICMPRequestedPackets(probe Canary) uint64 {
	if icmp, ok := probe.(*icmpCanary); ok && icmp.count > 0 {
		return uint64(icmp.count)
	}
	return 0
}
