package canary

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const udpType = "udp"

// udpCanary measures UDP round-trip latency and loss to a target that echoes
// datagrams (e.g. a probectl agent-to-agent responder or a UDP echo service). It
// sends token-tagged datagrams and matches the echoes by token + sequence. A
// non-echoing target shows as 100% loss — this is an echo-based probe.
type udpCanary struct {
	guard   *TargetGuard
	host    string
	port    string
	count   int
	payload int
	dscp    int
	timeout time.Duration
	spacing time.Duration
}

const udpHeaderLen = 10 // token(8) + seq(2)

// NewUDP builds a UDP echo-RTT canary. The target is host:port, or a host with
// the port in Params["port"]. Params: count, payload_bytes (>=10), dscp (0-63).
func NewUDP(cfg Config) (Canary, error) {
	host, port, err := splitTarget(cfg.Target, cfg.Params["port"])
	if err != nil {
		return nil, fmt.Errorf("udp: %w", err)
	}
	c := &udpCanary{host: host, port: port, count: 5, payload: 56, timeout: cfg.Timeout, guard: GuardFromParams(cfg.Params)}
	if err := c.guard.CheckHost(host); err != nil {
		return nil, fmt.Errorf("udp: %w", err)
	}
	if c.timeout <= 0 {
		c.timeout = 3 * time.Second
	}
	if err := intParam(cfg.Params, "count", &c.count, 1, 100000); err != nil {
		return nil, err
	}
	if err := intParam(cfg.Params, "payload_bytes", &c.payload, udpHeaderLen, 65000); err != nil {
		return nil, err
	}
	if err := intParam(cfg.Params, "dscp", &c.dscp, 0, 63); err != nil {
		return nil, err
	}
	return c, nil
}

// Describe returns the UDP canary spec.
func (c *udpCanary) Describe() Spec {
	return Spec{Type: udpType, Version: "1", Description: "UDP echo round-trip latency + loss"}
}

// Run sends c.count echo datagrams and reports round-trip stats.
func (c *udpCanary) Run(ctx context.Context) (Result, error) {
	start := time.Now()
	addr := net.JoinHostPort(c.host, c.port)
	res := Result{Type: udpType, Target: addr, StartedAt: start, Attributes: map[string]string{
		"network.transport": "udp",
		"server.address":    c.host,
		"server.port":       c.port,
	}}

	dialer := net.Dialer{Control: c.guard.DialControl(dialControl(c.dscp))}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("udp: dial %s: %w", addr, err)
	}
	defer conn.Close()

	rtts := c.echo(ctx, conn, start)
	res.Duration = time.Since(start)

	stats := computeLatencyStats(rtts, c.count)
	res.Metrics = stats.latencyMetrics("rtt")
	if stats.Received == 0 {
		res.Success = false
		res.Error = fmt.Sprintf("no UDP echoes from %s (%d sent)", addr, c.count)
	} else {
		res.Success = true
	}
	return res, nil
}

// echo sends count token-tagged datagrams and collects echoes, returning
// per-sequence RTTs (negative = no echo).
func (c *udpCanary) echo(ctx context.Context, conn net.Conn, start time.Time) []time.Duration {
	rtts := make([]time.Duration, c.count)
	for i := range rtts {
		rtts[i] = -1
	}
	token := make([]byte, 8)
	binary.BigEndian.PutUint64(token, uint64(start.UnixNano()))

	var mu sync.Mutex
	sendAt := make([]time.Time, c.count)
	deadline := start.Add(time.Duration(c.count-1)*c.spacing + c.timeout)
	_ = conn.SetReadDeadline(deadline)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			recvAt := time.Now()
			if n < udpHeaderLen || string(buf[:8]) != string(token) {
				continue
			}
			seq := int(binary.BigEndian.Uint16(buf[8:10]))
			if seq < 0 || seq >= c.count {
				continue
			}
			mu.Lock()
			if rtts[seq] < 0 && !sendAt[seq].IsZero() {
				rtts[seq] = recvAt.Sub(sendAt[seq])
			}
			mu.Unlock()
		}
	}()

	pkt := make([]byte, c.payload)
	copy(pkt, token)
	for seq := 0; seq < c.count; seq++ {
		if ctx.Err() != nil {
			break
		}
		binary.BigEndian.PutUint16(pkt[8:10], uint16(seq))
		mu.Lock()
		sendAt[seq] = time.Now()
		mu.Unlock()
		_, _ = conn.Write(pkt)
		if seq < c.count-1 && !sleepCtx(ctx, c.spacing) {
			break
		}
	}

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
	return rtts
}
