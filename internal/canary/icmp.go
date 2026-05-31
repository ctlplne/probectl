package canary

import (
	"bytes"
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
)

const icmpType = "icmp"

// icmpCanary measures ICMP echo loss, latency, and jitter to a target. It uses
// unprivileged datagram ICMP sockets (Linux IPPROTO_ICMP via ping_group_range)
// by default and falls back to raw sockets (CAP_NET_RAW); set the "privileged"
// param to prefer raw. It supports IPv4 and IPv6.
type icmpCanary struct {
	target     string
	count      int
	payload    int
	dscp       int
	continuous bool
	privileged bool
	timeout    time.Duration // wait for replies after the last send
	spacing    time.Duration // inter-packet gap (0 batch, 1s continuous)
}

// NewICMP builds an ICMP echo canary. Options come from Config.Params: count,
// payload_bytes, dscp (0-63), mode ("batch"|"continuous"), and privileged
// ("true" forces raw sockets). In continuous mode packets are paced at 1/sec and
// count defaults to the schedule interval in seconds.
func NewICMP(cfg Config) (Canary, error) {
	if cfg.Target == "" {
		return nil, errors.New("icmp: target is required")
	}
	c := &icmpCanary{target: cfg.Target, count: 5, payload: 56, timeout: cfg.Timeout}
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
	res.Attributes["icmp.mode"] = c.modeName()

	ipAddr, err := net.ResolveIPAddr("ip", c.target)
	if err != nil {
		return c.fail(res, fmt.Sprintf("resolve %s: %v", c.target, err)), nil
	}
	v6 := ipAddr.IP.To4() == nil
	res.Attributes["network.peer.address"] = ipAddr.IP.String()

	conn, raw, err := c.listen(v6)
	if err != nil {
		return Result{}, fmt.Errorf("icmp: open socket: %w", err)
	}
	defer conn.Close()
	c.setDSCP(conn, v6)

	rtts, sendOffsets := c.probe(ctx, conn, raw, v6, ipAddr.IP, start)
	res.Duration = time.Since(start)

	stats := computeICMPStats(rtts, c.count)
	res.Metrics = stats.metrics()
	if seqs, offs := dropRecord(rtts, sendOffsets); seqs != "" {
		res.Attributes["icmp.dropped_seqs"] = seqs
		res.Attributes["icmp.drop_send_offsets_ms"] = offs
	}
	if stats.Received == 0 {
		res.Success = false
		res.Error = fmt.Sprintf("100%% packet loss (0/%d)", c.count)
	} else {
		res.Success = true
	}
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
// lost) and per-sequence send offsets from start.
func (c *icmpCanary) probe(ctx context.Context, conn *icmp.PacketConn, raw, v6 bool, dst net.IP, start time.Time) (rtts, sendOffsets []time.Duration) {
	rtts = make([]time.Duration, c.count)
	sendOffsets = make([]time.Duration, c.count)
	for i := range rtts {
		rtts[i] = -1
	}

	token := make([]byte, 8)
	binary.BigEndian.PutUint64(token, uint64(start.UnixNano()))
	id := os.Getpid() & 0xffff

	var mu sync.Mutex
	sendAt := make([]time.Time, c.count)

	deadline := start.Add(time.Duration(c.count-1)*c.spacing + c.timeout)
	_ = conn.SetReadDeadline(deadline)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		proto := ianaProtoICMP
		if v6 {
			proto = ianaProtoICMPv6
		}
		buf := make([]byte, 1500)
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				return // deadline reached or socket closed
			}
			recvAt := time.Now()
			msg, perr := icmp.ParseMessage(proto, buf[:n])
			if perr != nil {
				continue
			}
			if msg.Type != ipv4.ICMPTypeEchoReply && msg.Type != ipv6.ICMPTypeEchoReply {
				continue
			}
			echo, ok := msg.Body.(*icmp.Echo)
			if !ok || !bytes.HasPrefix(echo.Data, token) {
				continue // not one of ours
			}
			if raw && echo.ID != id {
				continue
			}
			if echo.Seq < 0 || echo.Seq >= c.count {
				continue
			}
			mu.Lock()
			if rtts[echo.Seq] < 0 && !sendAt[echo.Seq].IsZero() {
				rtts[echo.Seq] = recvAt.Sub(sendAt[echo.Seq])
			}
			mu.Unlock()
		}
	}()

	var dstAddr net.Addr = &net.UDPAddr{IP: dst}
	if raw {
		dstAddr = &net.IPAddr{IP: dst}
	}

	for seq := 0; seq < c.count; seq++ {
		if ctx.Err() != nil {
			break
		}
		msg, err := buildEcho(v6, id, seq, token, c.payload)
		if err == nil {
			mu.Lock()
			sendAt[seq] = time.Now()
			sendOffsets[seq] = sendAt[seq].Sub(start)
			mu.Unlock()
			_, _ = conn.WriteTo(msg, dstAddr)
		}
		if seq < c.count-1 && !sleepCtx(ctx, c.spacing) {
			break
		}
	}

	// Wait for replies until every sequence is answered or the deadline passes,
	// then unblock the reader. Early-exit keeps a fully-successful batch fast
	// instead of always blocking for the whole timeout.
	for time.Now().Before(deadline) {
		mu.Lock()
		got := 0
		for _, d := range rtts {
			if d >= 0 {
				got++
			}
		}
		mu.Unlock()
		if got >= c.count {
			break
		}
		if !sleepCtx(ctx, 5*time.Millisecond) {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Now())
	wg.Wait()
	return rtts, sendOffsets
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
	data := make([]byte, payload)
	copy(data, token)
	for i := len(token); i < len(data); i++ {
		data[i] = byte(i % 256)
	}
	m := icmp.Message{Type: typ, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq, Data: data}}
	return m.Marshal(nil)
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
