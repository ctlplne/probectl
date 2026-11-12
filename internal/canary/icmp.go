// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/ctlplne/probectl/internal/crypto"
)

const icmpType = "icmp"

// icmpCanary measures ICMP echo loss, latency, and jitter to a target. It uses
// unprivileged datagram ICMP sockets (Linux IPPROTO_ICMP via ping_group_range)
// by default and falls back to raw sockets (CAP_NET_RAW); set the "privileged"
// param to prefer raw. It supports IPv4 and IPv6.
type icmpCanary struct {
	guard      *TargetGuard
	target     string
	count      int
	payload    int
	readBuffer int
	dscp       int
	continuous bool
	privileged bool
	timeout    time.Duration // wait for replies after the last send
	spacing    time.Duration // inter-packet gap (0 batch, 1s continuous)
}

// NewICMP builds an ICMP echo canary. Options come from Config.Params: count,
// payload_bytes, read_buffer_bytes, dscp (0-63), mode ("batch"|"continuous"), and privileged
// ("true" forces raw sockets). In continuous mode packets are paced at 1/sec and
// count defaults to the schedule interval in seconds.
func NewICMP(cfg Config) (Canary, error) {
	if cfg.Target == "" {
		return nil, errors.New("icmp: target is required")
	}
	guard := GuardFromParams(cfg.Params)
	if err := guard.CheckHost(cfg.Target); err != nil {
		return nil, fmt.Errorf("icmp: %w", err)
	}
	c := &icmpCanary{guard: guard, target: cfg.Target, count: 5, payload: 56, readBuffer: 1 << 20, timeout: cfg.Timeout}
	if c.timeout <= 0 {
		c.timeout = 3 * time.Second
	}

	p := cfg.Params
	if err := intParam(p, "count", &c.count, 1, 100000); err != nil {
		return nil, err
	}
	if err := intParam(p, "payload_bytes", &c.payload, 8, 65000); err != nil {
		return nil, err
	}
	// SO_RCVBUF is a signed 32-bit native socket option. This bounds the
	// option representation, not packet count, payload or output population.
	if err := intParam(p, "read_buffer_bytes", &c.readBuffer, 1, 1<<31-1); err != nil {
		return nil, err
	}
	if err := intParam(p, "dscp", &c.dscp, 0, 63); err != nil {
		return nil, err
	}
	if p["privileged"] == "true" {
		c.privileged = true
	}
	switch p["mode"] {
	case "", "batch":
	case "continuous":
		c.continuous = true
		c.spacing = time.Second
		if _, set := p["count"]; !set {
			c.count = clampInt(int(cfg.Interval/time.Second), 1, 3600)
		}
	default:
		return nil, fmt.Errorf("icmp: unknown mode %q (want batch|continuous)", p["mode"])
	}
	if c.payload < 8 {
		c.payload = 8 // room for the match token
	}
	return c, nil
}

// Describe returns the ICMP canary spec.
func (c *icmpCanary) Describe() Spec {
	return Spec{Type: icmpType, Version: "1", Description: "ICMP echo loss/latency/jitter"}
}

// Run performs one ICMP measurement. A probe failure (unreachable / 100% loss)
// is a Result with Success=false, never a returned error; a returned error is
// reserved for an internal fault such as a socket that cannot be opened.
func (c *icmpCanary) Run(ctx context.Context) (Result, error) {
	start := time.Now()
	res := Result{Type: icmpType, Target: c.target, StartedAt: start, Attributes: map[string]string{}}
	res.Attributes["probectl.icmp.mode"] = c.modeName()

	ipAddr, err := net.ResolveIPAddr("ip", c.target)
	if err != nil {
		return c.fail(res, fmt.Sprintf("resolve %s: %v", c.target, err)), nil
	}
	// SSRF guard (U-002): check the RESOLVED address and ping exactly that
	// address below — a rebinding name cannot swap in a private IP later.
	if err := c.guard.CheckNetIP(ipAddr.IP); err != nil {
		return c.fail(res, err.Error()), nil
	}
	v6 := ipAddr.IP.To4() == nil
	res.Attributes["network.peer.address"] = ipAddr.IP.String()

	conn, raw, err := c.listen(v6)
	if err != nil {
		return Result{}, fmt.Errorf("icmp: open socket: %w", err)
	}
	defer conn.Close()
	if err := c.setReadBuffer(conn, v6); err != nil {
		return Result{}, fmt.Errorf("icmp: receive buffer: %w", err)
	}
	c.setDSCP(conn, v6)

	rtts, sendOffsets, facts, err := c.probe(ctx, conn, raw, v6, ipAddr.IP, start)
	if err != nil {
		return Result{}, err
	}
	res.Duration = time.Since(start)
	res = c.measurementResult(res, rtts, sendOffsets, facts)
	res.Metrics["socket.read_buffer.requested_bytes"] = float64(c.readBuffer)
	return res, nil
}

// listen opens an ICMP socket, preferring unprivileged datagram sockets (or raw
// first when privileged is set) and falling back to the other. It reports
// whether the socket is raw (which affects reply matching and the dst address).
func (c *icmpCanary) listen(v6 bool) (conn *icmp.PacketConn, raw bool, err error) {
	udpNet, rawNet, addr := "udp4", "ip4:icmp", "0.0.0.0"
	if v6 {
		udpNet, rawNet, addr = "udp6", "ip6:ipv6-icmp", "::"
	}
	openUDP := func() (*icmp.PacketConn, bool, error) { pc, e := icmp.ListenPacket(udpNet, addr); return pc, false, e }
	openRaw := func() (*icmp.PacketConn, bool, error) { pc, e := icmp.ListenPacket(rawNet, addr); return pc, true, e }

	order := []func() (*icmp.PacketConn, bool, error){openUDP, openRaw}
	if c.privileged {
		order = []func() (*icmp.PacketConn, bool, error){openRaw, openUDP}
	}
	for _, open := range order {
		pc, isRaw, e := open()
		if e == nil {
			return pc, isRaw, nil
		}
		if err == nil {
			err = e
		}
	}
	return nil, false, err
}

// setDSCP sets the outgoing DSCP (best-effort; failures don't abort the probe).
func (c *icmpCanary) setDSCP(conn *icmp.PacketConn, v6 bool) {
	if c.dscp == 0 {
		return
	}
	tos := c.dscp << 2 // DSCP occupies the top 6 bits of the TOS / traffic-class byte
	if v6 {
		if p := conn.IPv6PacketConn(); p != nil {
			_ = p.SetTrafficClass(tos)
		}
		return
	}
	if p := conn.IPv4PacketConn(); p != nil {
		_ = p.SetTOS(tos)
	}
}

// probe sends c.count echo requests (paced by c.spacing) and collects replies
// until c.timeout past the last send. It returns per-sequence RTTs (negative =
// lost), per-sequence send offsets and complete local IO facts.
func (c *icmpCanary) probe(ctx context.Context, conn icmpProbeConn, raw, v6 bool, dst net.IP, start time.Time) ([]time.Duration, []time.Duration, ICMPMeasurement, error) {
	facts := ICMPMeasurement{TargetIP: dst.String(), StartedAt: start.UTC(), Expected: c.count}
	tokens, err := crypto.Random(8 * c.count)
	if err != nil {
		return nil, nil, facts, fmt.Errorf("icmp: probe challenge unavailable: %w", err)
	}
	state := icmpProbeState{rtts: make([]time.Duration, c.count), offsets: make([]time.Duration, c.count), sentAt: make([]time.Time, c.count), written: make([]bool, c.count), payload: icmpEchoPayload(tokens[:8], c.payload), challenges: make(map[uint64]int, c.count), id: os.Getpid() & 0xffff, raw: raw, v6: v6, responders: map[string]bool{}}
	for i := range state.rtts {
		state.rtts[i], state.offsets[i] = -1, -1
		challenge := binary.BigEndian.Uint64(tokens[i*8 : (i+1)*8])
		if _, collision := state.challenges[challenge]; collision {
			return nil, nil, facts, errors.New("icmp: probe challenge collision")
		}
		state.challenges[challenge] = i
	}
	deadline := start.Add(time.Duration(c.count-1)*c.spacing + c.timeout)
	ioDeadline := deadline
	if cancellation, ok := ctx.Deadline(); ok && cancellation.Before(ioDeadline) {
		ioDeadline = cancellation
	}
	if err := conn.SetReadDeadline(ioDeadline); err != nil {
		return nil, nil, facts, fmt.Errorf("icmp: read deadline: %w", err)
	}
	if err := conn.SetWriteDeadline(ioDeadline); err != nil {
		return nil, nil, facts, fmt.Errorf("icmp: write deadline: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()); _ = conn.SetWriteDeadline(time.Now()) })
	defer stop()
	var readers sync.WaitGroup
	readers.Add(1)
	go func() { defer readers.Done(); state.read(ctx, conn, deadline) }()
	var destination net.Addr = &net.UDPAddr{IP: dst}
	if raw {
		destination = &net.IPAddr{IP: dst}
	}
	for sequence := 0; sequence < c.count; sequence++ {
		if ctx.Err() != nil {
			break
		}
		facts.Attempted++
		packet, err := buildEcho(v6, state.id, sequence&0xffff, tokens[sequence*8:(sequence+1)*8], c.payload)
		if err != nil {
			facts.SendErrors++
		} else {
			state.mu.Lock()
			state.sentAt[sequence] = time.Now()
			n, writeErr := conn.WriteTo(packet, destination)
			if writeErr == nil && n == len(packet) {
				state.written[sequence] = true
				state.offsets[sequence] = state.sentAt[sequence].Sub(start)
				facts.Transmitted++
			} else {
				facts.SendErrors++
			}
			state.mu.Unlock()
		}
		if sequence < c.count-1 && !sleepCtx(ctx, c.spacing) {
			break
		}
	}
	for time.Now().Before(deadline) && state.received() < c.count {
		if !sleepCtx(ctx, 5*time.Millisecond) {
			break
		}
	}
	if err := conn.SetReadDeadline(time.Now()); err != nil {
		facts.IOFailed = true
		_ = conn.Close()
	}
	readers.Wait()
	facts = state.finish(ctx, facts, deadline)
	return state.rtts, state.offsets, facts, nil
}

func (c *icmpCanary) modeName() string {
	if c.continuous {
		return "continuous"
	}
	return "batch"
}

func (c *icmpCanary) fail(res Result, msg string) Result {
	res.Success = false
	res.Error = msg
	res.Duration = time.Since(res.StartedAt)
	if res.Metrics == nil {
		res.Metrics = map[string]float64{}
	}
	return res
}

// IANA protocol numbers for ICMP message parsing.
const (
	ianaProtoICMP   = 1
	ianaProtoICMPv6 = 58
)

// buildEcho marshals an ICMP echo request whose payload begins with token (used
// to match replies) and is padded to payload bytes.
func buildEcho(v6 bool, id, seq int, token []byte, payload int) ([]byte, error) {
	var typ icmp.Type = ipv4.ICMPTypeEcho
	if v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	data := icmpEchoPayload(token, payload)
	m := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: data}}
	return m.Marshal(nil)
}

func icmpEchoPayload(token []byte, payload int) []byte {
	data := make([]byte, payload)
	copy(data, token)
	for i := len(token); i < len(data); i++ {
		data[i] = byte(i % 256)
	}
	return data
}

func intParam(p map[string]string, key string, dst *int, lo, hi int) error {
	v, ok := p[key]
	if !ok || v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("icmp: %s: invalid integer %q", key, v)
	}
	if n < lo || n > hi {
		return fmt.Errorf("icmp: %s: %d out of range [%d,%d]", key, n, lo, hi)
	}
	*dst = n
	return nil
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// sleepCtx waits for d or until ctx is canceled; it returns false if canceled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
