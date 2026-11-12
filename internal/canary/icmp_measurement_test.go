// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type icmpMeasurementSocket struct {
	mode        string
	v6          bool
	peer        net.Addr
	packets     chan []byte
	done        chan struct{}
	once        sync.Once
	mu          sync.Mutex
	timer       *time.Timer
	readPackets int
	writes      int
}

func newICMPMeasurementSocket(t *testing.T, mode string, v6 bool) *icmpMeasurementSocket {
	t.Helper()
	ip := net.ParseIP("192.0.2.1")
	if v6 {
		ip = net.ParseIP("2001:db8::2")
	}
	socket := &icmpMeasurementSocket{mode: mode, v6: v6, peer: &net.IPAddr{IP: ip}, packets: make(chan []byte, 8), done: make(chan struct{})}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func (s *icmpMeasurementSocket) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	if time.Until(deadline) <= 0 {
		s.once.Do(func() { close(s.done) })
	} else {
		s.timer = time.AfterFunc(time.Until(deadline), func() { s.once.Do(func() { close(s.done) }) })
	}
	return nil
}
func (*icmpMeasurementSocket) SetWriteDeadline(time.Time) error { return nil }
func (s *icmpMeasurementSocket) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.once.Do(func() { close(s.done) })
	return nil
}
func (s *icmpMeasurementSocket) ReadFrom(buffer []byte) (int, net.Addr, error) {
	if s.mode == "read-error" {
		return 0, nil, errors.New("owned read failure")
	}
	select {
	case packet := <-s.packets:
		s.readPackets++
		return copy(buffer, packet), s.peer, nil
	case <-s.done:
		return 0, nil, os.ErrDeadlineExceeded
	}
}
func (s *icmpMeasurementSocket) WriteTo(packet []byte, _ net.Addr) (int, error) {
	s.writes++
	if s.mode == "last-only" && s.writes < 65537 {
		return len(packet), nil
	}
	if s.mode == "write-error" {
		return 0, errors.New("owned write failure")
	}
	if s.mode == "loss" || s.mode == "read-error" {
		return len(packet), nil
	}
	protocol := ianaProtoICMP
	var replyType icmp.Type = ipv4.ICMPTypeEchoReply
	if s.v6 {
		protocol, replyType = ianaProtoICMPv6, ipv6.ICMPTypeEchoReply
	}
	request, err := icmp.ParseMessage(protocol, packet)
	if err != nil {
		return 0, err
	}
	echo, ok := request.Body.(*icmp.Echo)
	if !ok {
		return 0, errors.New("owned echo fixture received another message")
	}
	echo.Data = append([]byte(nil), echo.Data...)
	switch s.mode {
	case "truncated":
		echo.Data = echo.Data[:8]
	case "corrupt":
		echo.Data[len(echo.Data)-1] ^= 1
	case "oversized":
		echo.Data = append(echo.Data, 1)
	}
	reply, err := (&icmp.Message{Type: replyType, Code: 0, Body: echo}).Marshal(nil)
	if err != nil {
		return 0, err
	}
	s.packets <- reply
	if s.mode == "short-write" {
		return len(packet) - 1, nil
	}
	return len(packet), nil
}

func TestICMPRejectsIncompleteEchoPayloads(t *testing.T) {
	for _, mode := range []string{"truncated", "corrupt", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			socket := newICMPMeasurementSocket(t, mode, false)
			probe := &icmpCanary{count: 1, payload: 56, timeout: 500 * time.Millisecond}
			rtts, _, _, err := probe.probe(t.Context(), socket, true, false, net.ParseIP("192.0.2.1"), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if socket.readPackets == 0 {
				t.Fatal("negative control never received its planted reply")
			}
			if rtts[0] >= 0 {
				t.Fatal("an incomplete or modified payload was counted as a successful echo")
			}
		})
	}
}

func TestICMPMeasurementRetainsLargeIPv4IPv6AndAnycastReplies(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "ipv6"}[v6], func(t *testing.T) {
			socket := newICMPMeasurementSocket(t, "reply", v6)
			target := net.ParseIP("192.0.2.1")
			if v6 {
				target = net.ParseIP("2001:db8::99")
			} // Anycast reply has a unicast source.
			probe := &icmpCanary{count: 1, payload: 4096, timeout: time.Second}
			rtts, offsets, facts, err := probe.probe(t.Context(), socket, true, v6, target, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if !facts.Complete() || facts.Expected != 1 || facts.Attempted != 1 || facts.Transmitted != 1 || facts.Replies != 1 || len(facts.Responders) != 1 || rtts[0] < 0 {
				t.Fatal("complete large echo facts were lost", facts)
			}
			if v6 && facts.Responders[0] != "2001:db8::2" {
				t.Fatal("actual anycast responder was replaced by the target", facts.Responders)
			}
			result := probe.measurementResult(Result{Attributes: map[string]string{}}, rtts, offsets, facts)
			if !result.Success || result.Metrics["packets.sent"] != 1 || result.Metrics["measurement.complete"] != 1 {
				t.Fatal("complete result lost observed packet counts", result)
			}
		})
	}
}

func TestICMPMeasurementSeparatesLocalFailuresFromNetworkLoss(t *testing.T) {
	for _, mode := range []string{"write-error", "short-write", "read-error", "loss"} {
		t.Run(mode, func(t *testing.T) {
			socket := newICMPMeasurementSocket(t, mode, false)
			probe := &icmpCanary{count: 1, payload: 56, timeout: 100 * time.Millisecond}
			rtts, offsets, facts, err := probe.probe(t.Context(), socket, true, false, net.ParseIP("192.0.2.1"), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			result := probe.measurementResult(Result{Attributes: map[string]string{}}, rtts, offsets, facts)
			if result.Success || result.ICMP == nil || result.Metrics["packets.requested"] != 1 || result.Metrics["packets.attempted"] != 1 {
				t.Fatal("failed IO produced successful or incomplete accounting", result)
			}
			if mode == "loss" {
				if !facts.Complete() || result.Metrics["loss.ratio"] != 1 || result.Metrics["packets.sent"] != 1 {
					t.Fatal("complete network loss lost its real transmission", facts, result.Metrics)
				}
			} else if facts.Complete() || !strings.Contains(result.Error, "ICMP") {
				t.Fatal("local failure became complete network evidence", facts, result.Error)
			}
			if mode == "write-error" || mode == "short-write" {
				if facts.Transmitted != 0 || facts.Replies != 0 || facts.SendErrors != 1 || result.Metrics["packets.sent"] != 0 {
					t.Fatal("unsent request or forged reply counted as transmitted", facts)
				}
				if _, present := result.Metrics["loss.ratio"]; present {
					t.Fatal("no transmission was reported as measured packet loss")
				}
				if result.Attributes["probectl.icmp.dropped_seqs"] != "" {
					t.Fatal("unsent request was reported as a dropped network packet")
				}
			}
		})
	}
}

func TestICMPMeasurementCancellationAndResultBusHaveNoCompleteAuthority(t *testing.T) {
	socket := newICMPMeasurementSocket(t, "loss", false)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	probe := &icmpCanary{count: 1, payload: 56, timeout: time.Second}
	_, _, facts, err := probe.probe(ctx, socket, true, false, net.ParseIP("192.0.2.1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if facts.Complete() || !facts.Canceled || facts.Attempted != 0 || facts.Transmitted != 0 {
		t.Fatal("canceled probe invented complete transmission", facts)
	}
	encoded, err := json.Marshal(Result{ICMP: &facts})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "TargetIP") || strings.Contains(string(encoded), "Responders") {
		t.Fatal("collector evidence escaped onto ordinary result JSON")
	}
	var received Result
	if err := json.Unmarshal([]byte(`{"ICMP":{"Expected":1,"Transmitted":1},"icmp":{"Expected":1}}`), &received); err != nil {
		t.Fatal(err)
	}
	if received.ICMP != nil {
		t.Fatal("ordinary result JSON manufactured collector-local evidence")
	}
}

func TestICMPMeasurementRetainsSequenceAboveWireRange(t *testing.T) {
	socket := newICMPMeasurementSocket(t, "last-only", false)
	probe := &icmpCanary{count: 65537, payload: 8, timeout: 3 * time.Second}
	rtts, _, facts, err := probe.probe(t.Context(), socket, false, false, net.ParseIP("192.0.2.1"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Complete() || facts.Transmitted != 65537 || facts.Replies != 1 || rtts[65536] < 0 || rtts[0] >= 0 {
		t.Fatal("the wrapped wire sequence was attributed to a different request", facts)
	}
}

// Linux net.IPConn reads the outer IPv4 header into the supplied buffer,
// then strips that header. Truncation has already happened at that point.
// This socket contract reproduces the kernel/stdlib boundary independently
// of the collector's echo matching and nonce checks.
type ipv4HeaderMeasurementSocket struct {
	*icmpMeasurementSocket
	headerBytes int
}

func (s *ipv4HeaderMeasurementSocket) ReadFrom(buffer []byte) (int, net.Addr, error) {
	select {
	case packet := <-s.packets:
		s.readPackets++
		raw := make([]byte, s.headerBytes+len(packet))
		raw[0] = 0x40 | byte(s.headerBytes/4)
		copy(raw[s.headerBytes:], packet)
		n := copy(buffer, raw)
		if n < s.headerBytes {
			return 0, nil, errors.New("IPv4 fixture header truncated")
		}
		copy(buffer, buffer[s.headerBytes:])
		return n - s.headerBytes, s.peer, nil
	case <-s.done:
		return 0, nil, os.ErrDeadlineExceeded
	}
}
func TestRawICMPv4KeepsCompleteEchoAcrossOuterHeaders(t *testing.T) {
	for _, headerBytes := range []int{20, 60} {
		t.Run(fmt.Sprint(headerBytes), func(t *testing.T) {
			socket := &ipv4HeaderMeasurementSocket{icmpMeasurementSocket: newICMPMeasurementSocket(t, "reply", false), headerBytes: headerBytes}
			probe := &icmpCanary{count: 1, payload: 4096, timeout: 80 * time.Millisecond}
			rtts, _, facts, err := probe.probe(t.Context(), socket, true, false, net.ParseIP("192.0.2.1"), time.Now())
			if err != nil || socket.readPackets != 1 || !facts.Complete() || facts.Replies != 1 || rtts[0] < 0 {
				t.Fatal("raw IPv4 stripped a truncated echo and reported false loss", headerBytes, facts, err)
			}
		})
	}
	socket := &ipv4HeaderMeasurementSocket{icmpMeasurementSocket: newICMPMeasurementSocket(t, "oversized", false), headerBytes: 60}
	probe := &icmpCanary{count: 1, payload: 4096, timeout: 80 * time.Millisecond}
	rtts, _, facts, err := probe.probe(t.Context(), socket, true, false, net.ParseIP("192.0.2.1"), time.Now())
	if err != nil || socket.readPackets != 1 || facts.Replies != 0 || rtts[0] >= 0 {
		t.Fatal("outer-header headroom accepted an oversized echo", facts, err)
	}
}
