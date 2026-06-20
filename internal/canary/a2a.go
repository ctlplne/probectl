// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Agent-to-agent (A2A) two-way measurement, TWAMP-lite style. The initiator
// timestamps each probe (T1) and sends it; the responder stamps receive (T2) and
// send (T3) times and echoes it; the initiator records receive (T4). From
// T1..T4 it computes round-trip = (T4-T1)-(T3-T2), forward one-way = T2-T1, and
// reverse one-way = T4-T3. One-way delays assume the two agents' clocks are
// synchronized (true within a host; use NTP across hosts — see docs).
const (
	a2aType         = "a2a"
	a2aReqBodyLen   = 20 // token(8) + seq(4) + T1(8)
	a2aReplyBodyLen = 36 // token(8) + seq(4) + T1(8) + T2(8) + T3(8)
	a2aMACLen       = 32 // HMAC-SHA256 via internal/crypto
	a2aReqLen       = a2aReqBodyLen + a2aMACLen
	a2aReplyLen     = a2aReplyBodyLen + a2aMACLen
	a2aReqMACDomain = "probectl-a2a-request-v1"
	a2aRepMACDomain = "probectl-a2a-reply-v1"
)

func a2aSessionKey(sessionID string) ([]byte, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, fmt.Errorf("a2a: session id is required for authenticated frames")
	}
	return []byte(sessionID), nil
}

func a2aMACInput(domain string, body []byte) []byte {
	out := make([]byte, 0, len(domain)+1+len(body))
	out = append(out, domain...)
	out = append(out, 0)
	out = append(out, body...)
	return out
}

func appendA2AMAC(key []byte, domain string, frame []byte, bodyLen int) {
	copy(frame[bodyLen:], crypto.Sign(key, a2aMACInput(domain, frame[:bodyLen])))
}

func verifyA2AMAC(key []byte, domain string, frame []byte, bodyLen int) bool {
	if len(frame) != bodyLen+a2aMACLen {
		return false
	}
	return crypto.Verify(key, a2aMACInput(domain, frame[:bodyLen]), frame[bodyLen:])
}

func encodeA2AReq(key, token []byte, seq uint32, t1 int64) []byte {
	b := make([]byte, a2aReqLen)
	copy(b[0:8], token)
	binary.BigEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint64(b[12:20], uint64(t1))
	appendA2AMAC(key, a2aReqMACDomain, b, a2aReqBodyLen)
	return b
}

// makeA2AReply echoes an authenticated request body and appends the responder's
// recv (t2) and send (t3) timestamps plus a reply MAC.
func makeA2AReply(key, reqBody []byte, t2, t3 int64) []byte {
	b := make([]byte, a2aReplyLen)
	copy(b[0:a2aReqBodyLen], reqBody[:a2aReqBodyLen])
	binary.BigEndian.PutUint64(b[20:28], uint64(t2))
	binary.BigEndian.PutUint64(b[28:36], uint64(t3))
	appendA2AMAC(key, a2aRepMACDomain, b, a2aReplyBodyLen)
	return b
}

type a2aReply struct {
	token      []byte
	seq        uint32
	t1, t2, t3 int64
}

func parseA2AReplyAuthenticated(key, b []byte) (a2aReply, bool) {
	if len(key) > 0 && !verifyA2AMAC(key, a2aRepMACDomain, b, a2aReplyBodyLen) {
		return a2aReply{}, false
	}
	if len(key) == 0 && len(b) != a2aReplyLen {
		return a2aReply{}, false
	}
	return a2aReply{
		token: b[0:8],
		seq:   binary.BigEndian.Uint32(b[8:12]),
		t1:    int64(binary.BigEndian.Uint64(b[12:20])),
		t2:    int64(binary.BigEndian.Uint64(b[20:28])),
		t3:    int64(binary.BigEndian.Uint64(b[28:36])),
	}, true
}

// A2AResponder is an authenticated responder listener for one brokered session.
type A2AResponder struct {
	mode string
	key  []byte
	udp  *net.UDPConn
	tcp  *net.TCPListener
	addr string
}

// StartA2AResponder opens a responder listener for mode ("udp"|"tcp") bound to
// host (port 0 → kernel-assigned). sessionID is the per-session MAC key handed
// to both agents over mTLS coordination. Call Addr to learn the bound address.
func StartA2AResponder(mode, host, sessionID string) (*A2AResponder, error) {
	key, err := a2aSessionKey(sessionID)
	if err != nil {
		return nil, err
	}
	switch mode {
	case "udp":
		ua, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, err
		}
		conn, err := net.ListenUDP("udp", ua)
		if err != nil {
			return nil, err
		}
		return &A2AResponder{mode: "udp", key: key, udp: conn, addr: conn.LocalAddr().String()}, nil
	case "tcp":
		ta, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, "0"))
		if err != nil {
			return nil, err
		}
		ln, err := net.ListenTCP("tcp", ta)
		if err != nil {
			return nil, err
		}
		return &A2AResponder{mode: "tcp", key: key, tcp: ln, addr: ln.Addr().String()}, nil
	default:
		return nil, fmt.Errorf("a2a: unknown mode %q (want udp|tcp)", mode)
	}
}

// Addr is the responder's bound listen address (host:port).
func (r *A2AResponder) Addr() string { return r.addr }

// Serve echoes probes until ctx is canceled, returning a responder-side Result.
// count is the expected probe count (from the broker) so the responder can report
// forward-direction loss.
func (r *A2AResponder) Serve(ctx context.Context, count int, peerAgentID string) Result {
	start := time.Now()
	var received int
	switch r.mode {
	case "udp":
		received = r.serveUDP(ctx, count)
	case "tcp":
		received = r.serveTCP(ctx, count)
	}
	res := Result{
		Type: a2aType, Target: peerAgentID, StartedAt: start, Duration: time.Since(start),
		Attributes: map[string]string{
			"a2a.role": "responder", "a2a.mode": r.mode,
			"network.transport": r.mode, "a2a.peer_agent_id": peerAgentID,
		},
		Metrics: map[string]float64{"packets.sent": float64(count), "packets.received": float64(received)},
	}
	if count > 0 {
		res.Metrics["loss.ratio"] = round(float64(count-received)/float64(count), 4) // forward-direction loss
	}
	res.Success = received > 0
	if received == 0 {
		res.Error = "a2a responder received no probes"
	}
	return res
}

func (r *A2AResponder) serveUDP(ctx context.Context, count int) int {
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { <-sctx.Done(); _ = r.udp.Close() }()
	received := 0
	buf := make([]byte, 2048)
	for {
		n, addr, err := r.udp.ReadFrom(buf)
		if err != nil {
			return received
		}
		t2 := time.Now().UnixNano()
		if !verifyA2AMAC(r.key, a2aReqMACDomain, buf[:n], a2aReqBodyLen) {
			continue
		}
		_, _ = r.udp.WriteTo(makeA2AReply(r.key, buf[:a2aReqBodyLen], t2, time.Now().UnixNano()), addr)
		received++
		if count > 0 && received >= count {
			return received
		}
	}
}

func (r *A2AResponder) serveTCP(ctx context.Context, count int) int {
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() { <-sctx.Done(); _ = r.tcp.Close() }()
	var mu sync.Mutex
	received := 0
	var wg sync.WaitGroup
	for {
		conn, err := r.tcp.Accept()
		if err != nil {
			break
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			go func() { <-sctx.Done(); _ = c.Close() }()
			req := make([]byte, a2aReqLen)
			for {
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				t2 := time.Now().UnixNano()
				if !verifyA2AMAC(r.key, a2aReqMACDomain, req, a2aReqBodyLen) {
					continue
				}
				if _, err := c.Write(makeA2AReply(r.key, req[:a2aReqBodyLen], t2, time.Now().UnixNano())); err != nil {
					return
				}
				mu.Lock()
				received++
				full := count > 0 && received >= count
				mu.Unlock()
				if full {
					stop()
					return
				}
			}
		}(conn)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	return received
}

// RunA2AInitiator connects to a responder at addr and runs a two-way
// authenticated measurement, returning an initiator-side Result with round-trip
// plus forward/reverse one-way metrics. A dial/socket failure is an internal
// error; lost probes are reported as loss, not an error.
func RunA2AInitiator(ctx context.Context, mode, addr string, count int, timeout time.Duration, peerAgentID, sessionID string) (Result, error) {
	if count <= 0 {
		count = 5
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	start := time.Now()
	res := Result{Type: a2aType, Target: addr, StartedAt: start, Attributes: map[string]string{
		"a2a.role": "initiator", "a2a.mode": mode,
		"network.transport": mode, "a2a.peer_agent_id": peerAgentID,
	}}

	key, err := a2aSessionKey(sessionID)
	if err != nil {
		return Result{}, err
	}
	token, err := crypto.Random(8)
	if err != nil {
		return Result{}, err
	}

	var rtt, fwd, rev []time.Duration
	switch mode {
	case "udp":
		rtt, fwd, rev, err = a2aInitiate(ctx, "udp", addr, count, timeout, key, token, false)
	case "tcp":
		rtt, fwd, rev, err = a2aInitiate(ctx, "tcp", addr, count, timeout, key, token, true)
	default:
		return Result{}, fmt.Errorf("a2a: unknown mode %q (want udp|tcp)", mode)
	}
	if err != nil {
		return Result{}, fmt.Errorf("a2a initiator: %w", err)
	}
	res.Duration = time.Since(start)

	stats := computeLatencyStats(rtt, count)
	res.Metrics = stats.latencyMetrics("rtt")
	if f := computeLatencyStats(fwd, count); f.Received > 0 {
		res.Metrics["forward.avg.ms"] = round(f.AvgMs, 3)
		res.Metrics["forward.max.ms"] = round(f.MaxMs, 3)
	}
	if rv := computeLatencyStats(rev, count); rv.Received > 0 {
		res.Metrics["reverse.avg.ms"] = round(rv.AvgMs, 3)
		res.Metrics["reverse.max.ms"] = round(rv.MaxMs, 3)
	}
	if stats.Received == 0 {
		res.Success = false
		res.Error = fmt.Sprintf("no a2a echoes from %s (%d sent)", addr, count)
	} else {
		res.Success = true
	}
	return res, nil
}

// a2aInitiate sends count probes and collects replies, returning per-sequence
// round-trip, forward, and reverse samples (negative = no reply). stream=true
// frames replies over a TCP stream; otherwise each reply is one datagram.
func a2aInitiate(ctx context.Context, network, addr string, count int, timeout time.Duration, key, token []byte, stream bool) (rtt, fwd, rev []time.Duration, err error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, nil, nil, err
	}
	defer conn.Close()

	rtt, fwd, rev = sentinelSlice(count), sentinelSlice(count), sentinelSlice(count)
	sendT1 := make([]int64, count)
	var mu sync.Mutex

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)

	record := func(rep a2aReply, t4 int64) {
		if !bytes.Equal(rep.token, token) || int(rep.seq) >= count {
			return
		}
		mu.Lock()
		if rtt[rep.seq] < 0 && sendT1[rep.seq] != 0 {
			rtt[rep.seq] = time.Duration((t4 - rep.t1) - (rep.t3 - rep.t2))
			fwd[rep.seq] = time.Duration(rep.t2 - rep.t1)
			rev[rep.seq] = time.Duration(t4 - rep.t3)
		}
		mu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if stream {
			rb := make([]byte, a2aReplyLen)
			for {
				if _, e := io.ReadFull(conn, rb); e != nil {
					return
				}
				t4 := time.Now().UnixNano()
				if rep, ok := parseA2AReplyAuthenticated(key, rb); ok {
					record(rep, t4)
				}
			}
		}
		buf := make([]byte, 2048)
		for {
			n, e := conn.Read(buf)
			if e != nil {
				return
			}
			t4 := time.Now().UnixNano()
			if rep, ok := parseA2AReplyAuthenticated(key, buf[:n]); ok {
				record(rep, t4)
			}
		}
	}()

	for seq := 0; seq < count; seq++ {
		if ctx.Err() != nil {
			break
		}
		t1 := time.Now().UnixNano()
		mu.Lock()
		sendT1[seq] = t1
		mu.Unlock()
		if _, e := conn.Write(encodeA2AReq(key, token, uint32(seq), t1)); e != nil {
			break
		}
	}

	for time.Now().Before(deadline) {
		mu.Lock()
		got := 0
		for _, d := range rtt {
			if d >= 0 {
				got++
			}
		}
		mu.Unlock()
		if got >= count {
			break
		}
		if !sleepCtx(ctx, 5*time.Millisecond) {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Now())
	wg.Wait()
	return rtt, fwd, rev, nil
}

func sentinelSlice(n int) []time.Duration {
	s := make([]time.Duration, n)
	for i := range s {
		s[i] = -1
	}
	return s
}
