// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

// Voice/RTP canary (S47c, F21): an RTP-based voice test measuring MOS
// (ITU-T G.107 E-model, simplified), RFC 3550 interarrival jitter, and
// packet loss along the path. It streams REAL RTP packets (version-2
// header, codec payload type, codec cadence + payload size) to a target
// that echoes datagrams — a probectl agent responder or any UDP echo
// service — and scores the path from the echoes.
//
// Honesty about the model (the S47c watch-out): this is the SIMPLIFIED
// E-model for transport monitoring — R = R0 − Id(delay) − Ie,eff(codec,
// loss), with the default R0 = 93.2 and no advantage/simultaneous-
// impairment terms. One-way delay is estimated as RTT/2 plus codec frame
// delay plus a jitter buffer; the estimate and the model variant ride the
// result attributes so a MOS is never mistaken for a measured, calibrated
// listening score. Echo-based realism: a non-echoing target is 100% loss.

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

const voiceType = "voice"

// codecProfile pins one codec's RTP framing + its G.113 E-model parameters
// (Ie = equipment impairment, Bpl = packet-loss robustness).
type codecProfile struct {
	Name         string
	PayloadType  byte    // RTP PT
	FrameMs      int     // packetization interval
	PayloadBytes int     // RTP payload per packet
	SamplesPerPk uint32  // RTP timestamp increment (8 kHz clock)
	Ie           float64 // G.113 equipment impairment factor
	Bpl          float64 // G.113 packet-loss robustness factor
	CodecDelayMs float64 // frame + lookahead delay contributed by the codec
}

// voiceCodecs are the supported presets. Narrowband only — the default
// R0 = 93.2 E-model is a narrowband model; wideband variants are a
// different calculation (documented out of scope).
var voiceCodecs = map[string]codecProfile{
	"g711": {Name: "g711", PayloadType: 0, FrameMs: 20, PayloadBytes: 160, SamplesPerPk: 160,
		Ie: 0, Bpl: 25.1, CodecDelayMs: 20},
	"g729": {Name: "g729", PayloadType: 18, FrameMs: 20, PayloadBytes: 20, SamplesPerPk: 160,
		Ie: 11, Bpl: 19, CodecDelayMs: 25},
}

// rtpHeaderLen is the fixed RTP header size (no CSRC, no extensions).
const rtpHeaderLen = 12

// voiceCanary streams an RTP-framed probe call and scores the path.
type voiceCanary struct {
	guard   *TargetGuard
	host    string
	port    string
	codec   codecProfile
	seconds int
	dscp    int
	timeout time.Duration
}

// NewVoice builds the RTP voice canary. Target is host:port (or Params
// "port"). Params: codec (g711|g729), duration_seconds (1-10), dscp (0-63;
// voice traffic is conventionally EF=46).
func NewVoice(cfg Config) (Canary, error) {
	host, port, err := splitTarget(cfg.Target, cfg.Params["port"])
	if err != nil {
		return nil, fmt.Errorf("voice: %w", err)
	}
	c := &voiceCanary{host: host, port: port, codec: voiceCodecs["g711"], seconds: 3, dscp: 46, timeout: cfg.Timeout, guard: GuardFromParams(cfg.Params)}
	if err := c.guard.CheckHost(host); err != nil {
		return nil, fmt.Errorf("voice: %w", err)
	}
	if c.timeout <= 0 {
		c.timeout = 3 * time.Second
	}
	if name, ok := cfg.Params["codec"]; ok {
		profile, known := voiceCodecs[strings.ToLower(strings.TrimSpace(name))]
		if !known {
			return nil, fmt.Errorf("voice: unknown codec %q (g711, g729)", name)
		}
		c.codec = profile
	}
	if err := intParam(cfg.Params, "duration_seconds", &c.seconds, 1, 10); err != nil {
		return nil, err
	}
	if err := intParam(cfg.Params, "dscp", &c.dscp, 0, 63); err != nil {
		return nil, err
	}
	return c, nil
}

// Describe returns the voice canary spec.
func (c *voiceCanary) Describe() Spec {
	return Spec{Type: voiceType, Version: "1",
		Description: "RTP voice-quality probe: MOS (ITU-T E-model), jitter, loss"}
}

// Run streams one simulated call and reports MOS/jitter/loss.
func (c *voiceCanary) Run(ctx context.Context) (Result, error) {
	start := time.Now()
	addr := net.JoinHostPort(c.host, c.port)
	count := c.seconds * 1000 / c.codec.FrameMs
	res := Result{Type: voiceType, Target: addr, StartedAt: start, Attributes: map[string]string{
		"network.transport":      "udp",
		"server.address":         c.host,
		"server.port":            c.port,
		"voice.codec":            c.codec.Name,
		"voice.model":            "itu-t-g107-e-model-simplified",
		"voice.method":           "rtp-udp-echo-reflection",
		"voice.one_way_estimate": "rtt/2 + codec + jitter buffer",
	}}

	dialer := net.Dialer{Control: c.guard.DialControl(dialControl(c.dscp))}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("voice: dial %s: %w", addr, err)
	}
	defer conn.Close()

	sendAt, recvAt := c.stream(ctx, conn, start, count)
	res.Duration = time.Since(start)

	rtts := make([]time.Duration, count)
	for i := range rtts {
		rtts[i] = -1
		if !recvAt[i].IsZero() {
			rtts[i] = recvAt[i].Sub(sendAt[i])
		}
	}
	stats := computeLatencyStats(rtts, count)
	res.Metrics = stats.latencyMetrics("rtt")

	if stats.Received == 0 {
		res.Success = false
		res.Error = fmt.Sprintf("no RTP echoes from %s (%d sent) — voice path unmeasurable", addr, count)
		return res, nil
	}
	res.Success = true

	jitterMs := rfc3550JitterMs(sendAt, recvAt)
	jbMs := jitterBufferMs(jitterMs)
	oneWayMs := stats.AvgMs/2 + c.codec.CodecDelayMs + jbMs
	lossPct := stats.LossRatio * 100
	r := eModelR(oneWayMs, lossPct, c.codec)
	res.Metrics["voice.mos"] = round(mosFromR(r), 2)
	res.Metrics["voice.r_factor"] = round(r, 1)
	res.Metrics["voice.jitter.ms"] = round(jitterMs, 3)
	res.Metrics["voice.one_way.ms"] = round(oneWayMs, 2)
	res.Metrics["voice.loss.pct"] = round(lossPct, 2)
	res.Attributes["probectl.voice.jitter_buffer_ms"] = fmt.Sprintf("%.0f", jbMs)
	return res, nil
}

// stream sends count RTP packets at codec cadence and collects echo arrival
// times, matched by SSRC + sequence.
func (c *voiceCanary) stream(ctx context.Context, conn net.Conn, start time.Time, count int) (sendAt, recvAt []time.Time) {
	sendAt = make([]time.Time, count)
	recvAt = make([]time.Time, count)
	ssrc := uint32(start.UnixNano())
	spacing := time.Duration(c.codec.FrameMs) * time.Millisecond
	deadline := start.Add(time.Duration(count)*spacing + c.timeout)
	_ = conn.SetReadDeadline(deadline)

	var mu sync.Mutex
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
			at := time.Now()
			if n < rtpHeaderLen || buf[0]>>6 != 2 { // RTP version 2
				continue
			}
			if binary.BigEndian.Uint32(buf[8:12]) != ssrc {
				continue // not our stream
			}
			seq := int(binary.BigEndian.Uint16(buf[2:4]))
			if seq < 0 || seq >= count {
				continue
			}
			mu.Lock()
			if recvAt[seq].IsZero() && !sendAt[seq].IsZero() {
				recvAt[seq] = at
			}
			mu.Unlock()
		}
	}()

	pkt := make([]byte, rtpHeaderLen+c.codec.PayloadBytes)
	pkt[0] = 0x80 // V=2, no padding/extension/CSRC
	pkt[1] = c.codec.PayloadType
	binary.BigEndian.PutUint32(pkt[8:12], ssrc)
	var ts uint32
	for seq := 0; seq < count; seq++ {
		if ctx.Err() != nil {
			break
		}
		binary.BigEndian.PutUint16(pkt[2:4], uint16(seq))
		binary.BigEndian.PutUint32(pkt[4:8], ts)
		ts += c.codec.SamplesPerPk
		mu.Lock()
		sendAt[seq] = time.Now()
		mu.Unlock()
		_, _ = conn.Write(pkt)
		if seq < count-1 && !sleepCtx(ctx, spacing) {
			break
		}
	}

	// Wait out stragglers until every echo arrived or the deadline passes.
	for time.Now().Before(deadline) {
		mu.Lock()
		got := 0
		for i := range recvAt {
			if !recvAt[i].IsZero() || sendAt[i].IsZero() {
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
	return sendAt, recvAt
}

// rfc3550JitterMs computes the RFC 3550 §6.4.1 interarrival jitter estimator
// over consecutively received packets: J += (|D| − J) / 16, where D is the
// difference in transit-time deltas between successive packets.
func rfc3550JitterMs(sendAt, recvAt []time.Time) float64 {
	var j float64
	prev := -1
	for i := range recvAt {
		if recvAt[i].IsZero() {
			continue
		}
		if prev >= 0 {
			d := recvAt[i].Sub(recvAt[prev]) - sendAt[i].Sub(sendAt[prev])
			dMs := math.Abs(float64(d) / float64(time.Millisecond))
			j += (dMs - j) / 16
		}
		prev = i
	}
	return j
}

// jitterBufferMs models the de-jitter buffer a real endpoint would add:
// twice the measured jitter, floored at a typical 40 ms, capped at 120 ms.
func jitterBufferMs(jitterMs float64) float64 {
	jb := 2 * jitterMs
	if jb < 40 {
		jb = 40
	}
	if jb > 120 {
		jb = 120
	}
	return jb
}

// eModelR computes the simplified ITU-T G.107 transmission rating:
//
//	R = R0 − Id − Ie,eff
//	Id     = 0.024·d + 0.11·(d − 177.3)·H(d − 177.3)        (G.107 delay term)
//	Ie,eff = Ie + (95 − Ie) · Ppl / (Ppl + Bpl)             (G.107 §7.2, random loss)
//
// with R0 = 93.2 (the default-parameter rating) and no advantage factor —
// a deliberately conservative, transport-only variant.
func eModelR(oneWayMs, lossPct float64, codec codecProfile) float64 {
	id := 0.024 * oneWayMs
	if oneWayMs > 177.3 {
		id += 0.11 * (oneWayMs - 177.3)
	}
	ieEff := codec.Ie + (95-codec.Ie)*lossPct/(lossPct+codec.Bpl)
	return 93.2 - id - ieEff
}

// mosFromR maps an R factor onto MOS (G.107 Annex B): 1 below R=0, 4.5
// above R=100, the standard cubic in between.
func mosFromR(r float64) float64 {
	switch {
	case r <= 0:
		return 1
	case r >= 100:
		return 4.5
	default:
		return 1 + 0.035*r + r*(r-60)*(100-r)*7e-6
	}
}
