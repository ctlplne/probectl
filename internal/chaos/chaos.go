// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package chaos is probectl's network fault injector (S48, F47): a small
// in-process UDP proxy that applies latency / jitter / loss / partition to
// the traffic explicitly pointed at it, so the platform's own observability
// can be validated against KNOWN faults — "we injected 200ms + 50% loss;
// did the canaries, SLO burn alerts, and views catch it?" A self-test of
// efficacy, not a feature that touches production traffic.
//
// Blast radius by construction: the proxy only perturbs traffic addressed
// to ITS listener — nothing is intercepted, no kernel/qdisc state is
// touched, no agent or tenant traffic is affected unless a test target is
// explicitly pointed at the proxy address. Faults are config (the F47
// contract), mutable mid-run so a test can flip a healthy path into a
// degraded one and back. This is aligned with guardrail 8's spirit: the
// injector ships as a harness, is never wired into the control plane's
// serving path, and cannot be reached from any API.
package chaos

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// Fault is the chaos-injection config (the F47 contract): what to do to
// each datagram passing through the proxy.
type Fault struct {
	// LatencyMs delays each forwarded datagram (one way — a round trip
	// through the proxy adds ~2× on echo paths).
	LatencyMs int `json:"latency_ms"`
	// JitterMs adds a uniform ±JitterMs to each delay.
	JitterMs int `json:"jitter_ms"`
	// LossPct drops each datagram with this probability (0–100).
	LossPct float64 `json:"loss_pct"`
	// Partition drops EVERYTHING — a full blackhole.
	Partition bool `json:"partition"`
}

// Validate bounds the fault (fail closed on nonsense).
func (f Fault) Validate() error {
	if f.LatencyMs < 0 || f.LatencyMs > 60_000 {
		return fmt.Errorf("chaos: latency_ms %d out of range [0,60000]", f.LatencyMs)
	}
	// RESIL-008: jitter is bounded relative to latency. The previous expression
	// `JitterMs > LatencyMs && JitterMs > 1000` bound to the wrong precedence
	// (an && riding the ||), so Fault{LatencyMs:0, JitterMs:500} slipped through:
	// a ±500ms swing around a 0ms base is nonsensical (and underflows to a
	// negative delay). Jitter must be non-negative and may exceed the base
	// latency by at most a small slack (100ms) — so a tiny base latency can
	// still carry a little jitter, but a swing that dwarfs the latency is
	// rejected.
	const jitterSlackMs = 100
	if f.JitterMs < 0 || f.JitterMs > f.LatencyMs+jitterSlackMs {
		return fmt.Errorf("chaos: jitter_ms %d out of range (must be in [0, latency_ms+%d])", f.JitterMs, jitterSlackMs)
	}
	if f.LossPct < 0 || f.LossPct > 100 {
		return fmt.Errorf("chaos: loss_pct %.1f out of range [0,100]", f.LossPct)
	}
	return nil
}

// UDPProxy forwards datagrams listener↔target, applying the current Fault in
// both directions. One canary pointed at Addr() experiences the fault as if
// the network path itself were degraded.
type UDPProxy struct {
	listener *net.UDPConn
	target   *net.UDPAddr

	mu    sync.Mutex
	fault Fault
	rng   *rand.Rand

	// client tracking: the proxy is built for probe traffic (one or a few
	// flows), so a simple last-client model is enough and stays bounded.
	clientMu sync.Mutex
	client   *net.UDPAddr

	upstream *net.UDPConn
	wg       sync.WaitGroup
}

// NewUDPProxy builds a proxy on an ephemeral local port toward target
// ("host:port"). Faults start at the given value (Validate'd, fail closed).
func NewUDPProxy(target string, f Fault) (*UDPProxy, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	tAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, fmt.Errorf("chaos: target %s: %w", target, err)
	}
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, fmt.Errorf("chaos: listen: %w", err)
	}
	up, err := net.DialUDP("udp", nil, tAddr)
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("chaos: dial target: %w", err)
	}
	return &UDPProxy{
		listener: ln, target: tAddr, fault: f, upstream: up,
		rng: rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec // fault dice, not crypto
	}, nil
}

// Addr is the proxy's listen address — point the canary target here.
func (p *UDPProxy) Addr() string { return p.listener.LocalAddr().String() }

// SetFault swaps the active fault mid-run (the "inject" action of a chaos
// run). Invalid faults are rejected, keeping the previous one.
func (p *UDPProxy) SetFault(f Fault) error {
	if err := f.Validate(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fault = f
	return nil
}

// currentFault snapshots the active fault.
func (p *UDPProxy) currentFault() Fault {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fault
}

// roll decides one datagram's fate under f: dropped, or delayed by d.
func (p *UDPProxy) roll(f Fault) (drop bool, delay time.Duration) {
	if f.Partition {
		return true, 0
	}
	if f.LossPct > 0 {
		p.mu.Lock()
		dice := p.rng.Float64() * 100
		p.mu.Unlock()
		if dice < f.LossPct {
			return true, 0
		}
	}
	delayMs := float64(f.LatencyMs)
	if f.JitterMs > 0 {
		p.mu.Lock()
		delayMs += (p.rng.Float64()*2 - 1) * float64(f.JitterMs)
		p.mu.Unlock()
		if delayMs < 0 {
			delayMs = 0
		}
	}
	return false, time.Duration(delayMs * float64(time.Millisecond))
}

// Run pumps datagrams both ways until ctx ends. It blocks.
func (p *UDPProxy) Run(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		_ = p.listener.Close()
		_ = p.upstream.Close()
	}()
	defer close(done)

	// Downstream → upstream.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		buf := make([]byte, 64<<10)
		for {
			n, from, err := p.listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			p.clientMu.Lock()
			p.client = from
			p.clientMu.Unlock()
			p.forward(ctx, append([]byte(nil), buf[:n]...), p.upstream.Write)
		}
	}()

	// Upstream → downstream (back to the last client).
	buf := make([]byte, 64<<10)
	for {
		n, err := p.upstream.Read(buf)
		if err != nil {
			p.wg.Wait()
			return ctx.Err()
		}
		pkt := append([]byte(nil), buf[:n]...)
		p.forward(ctx, pkt, func(b []byte) (int, error) {
			p.clientMu.Lock()
			cl := p.client
			p.clientMu.Unlock()
			if cl == nil {
				return 0, nil
			}
			return p.listener.WriteToUDP(b, cl)
		})
	}
}

// forward applies the fault to one datagram and writes it (async when
// delayed, so a delayed packet never blocks the pump).
func (p *UDPProxy) forward(ctx context.Context, pkt []byte, write func([]byte) (int, error)) {
	drop, delay := p.roll(p.currentFault())
	if drop {
		return
	}
	if delay <= 0 {
		_, _ = write(pkt)
		return
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTimer(delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			_, _ = write(pkt)
		}
	}()
}
