// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureEmitter records emitted batches for assertions.
type captureEmitter struct {
	mu   sync.Mutex
	recs []Record
}

func (c *captureEmitter) Emit(_ context.Context, recs []Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recs = append(c.recs, recs...)
	return nil
}

func (c *captureEmitter) snapshot() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Record(nil), c.recs...)
}

func testConfig() *Config {
	cfg := Default()
	cfg.TenantID = "t-acme"
	cfg.AgentID = "agent-1"
	cfg.NetFlow = ListenerConfig{Enabled: true, Listen: "127.0.0.1:0"}
	cfg.IPFIX = ListenerConfig{Enabled: false}
	cfg.SFlow = ListenerConfig{Enabled: true, Listen: "127.0.0.1:0"}
	cfg.FlushInterval = 30 * time.Millisecond
	cfg.BatchSize = 8
	return cfg
}

// TestDecodeSafelyRecoversFromPanic: FUZZ-006. A decoder that panics on a
// sentinel input must not crash the read loop — decodeSafely recovers, counts a
// decode error, returns no records, and a subsequent good decode still works.
func TestDecodeSafelyRecoversFromPanic(t *testing.T) {
	c, err := New(testConfig(), &captureEmitter{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	c.decodeFn = func(pkt []byte, _ string, _ time.Time) ([]Record, int, error) {
		if len(pkt) == 1 && pkt[0] == 0xFF {
			panic("hostile datagram")
		}
		return []Record{{}}, 0, nil
	}

	// The panicking packet must be survived and counted, not propagated.
	recs, _, derr := c.decodeSafely([]byte{0xFF}, "10.0.0.1", "netflow", time.Now())
	if recs != nil {
		t.Errorf("panic path returned %d records, want 0", len(recs))
	}
	if derr == nil {
		t.Error("panic must surface as a decode error, not be swallowed silently")
	}
	if got := c.StatsSnapshot().DecodeErrors; got != 1 {
		t.Errorf("DecodeErrors = %d, want 1 after a recovered panic", got)
	}
	// The loop keeps working: a non-sentinel packet decodes normally.
	recs, _, derr = c.decodeSafely([]byte{0x01}, "10.0.0.1", "netflow", time.Now())
	if derr != nil || len(recs) != 1 {
		t.Errorf("post-panic decode = (%d recs, %v), want (1, nil) — loop did not recover", len(recs), derr)
	}
}

func sendUDP(t *testing.T, addr string, pkt []byte) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestCollectorEndToEnd sends real datagrams (v5 + v9 template/data + sFlow)
// over UDP and asserts tenant-bound records reach the emitter.
func TestCollectorEndToEnd(t *testing.T) {
	em := &captureEmitter{}
	c, err := New(testConfig(), em, slog.Default())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Close()

	nfAddr, sfAddr := c.localAddr("netflow"), c.localAddr("sflow")
	if nfAddr == "" || sfAddr == "" {
		t.Fatalf("listeners not bound: nf=%q sf=%q", nfAddr, sfAddr)
	}
	if c.localAddr("ipfix") != "" {
		t.Fatal("ipfix listener bound although disabled")
	}

	unix := uint32(time.Now().Unix())
	// v5 + v9 share the netflow socket (version-sniffed).
	sendUDP(t, nfAddr, buildNF5(1000, unix, 0, []nf5rec{{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, pkts: 1, bytes: 64, proto: 6, sport: 1, dport: 2,
	}}))
	// NetFlow v9 data can only decode once its template is registered. The
	// socket is drained by a worker POOL, so a one-shot template-then-data
	// pair can be processed out of order (data first → a correct TemplateMiss
	// per RFC 7011 §8, but then the record is dropped). Real exporters resend
	// templates periodically; mimic that by resending the v9 pair until the
	// record lands — making the test independent of worker scheduling and of
	// kernel UDP-buffer drops under -race load.
	sendV9 := func() {
		sendUDP(t, nfAddr, buildNF9Template(1000, unix, 7, 260, nf9V4Fields))
		sendUDP(t, nfAddr, buildNF9Data(1000, unix, 7, 260, [][]byte{
			nf9V4Row([4]byte{10, 0, 0, 3}, [4]byte{10, 0, 0, 4}, 5, 6, 17, 128, 2, 0, 0),
		}))
	}
	sendV9()
	hdr := buildEthIPv4TCP(0, [4]byte{10, 0, 0, 5}, [4]byte{10, 0, 0, 6}, 80, 1024, 0x10, 6)
	sendUDP(t, sfAddr, buildSFlowRaw(64, 1, 2, hdr, false, false))

	deadline := time.Now().Add(3 * time.Second)
	for {
		recs := em.snapshot()
		if len(recs) >= 3 {
			byProto := map[string]int{}
			for _, r := range recs {
				byProto[r.Protocol]++
				if r.TenantID != "t-acme" || r.AgentID != "agent-1" {
					t.Fatalf("record not tenant-bound: %+v", r)
				}
				if r.Exporter != "127.0.0.1" {
					t.Fatalf("exporter = %q, want 127.0.0.1", r.Exporter)
				}
			}
			if byProto[ProtoNetFlow5] < 1 || byProto[ProtoNetFlow9] < 1 || byProto[ProtoSFlow5] < 1 {
				t.Fatalf("missing protocols in %v", byProto)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; got %d records, stats %+v", len(recs), c.StatsSnapshot())
		}
		sendV9() // resend the template+data pair (exporter-style retransmit)
		time.Sleep(10 * time.Millisecond)
	}

	s := c.StatsSnapshot()
	if s.Packets < 4 || s.Records < 3 {
		t.Errorf("stats = %+v", s)
	}
	// Garbage must be counted, not crash anything.
	sendUDP(t, nfAddr, []byte{0xDE, 0xAD})
	deadline = time.Now().Add(2 * time.Second)
	for c.StatsSnapshot().DecodeErrors == 0 {
		if time.Now().After(deadline) {
			t.Fatal("decode error not counted for garbage datagram")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestCollectorAllowsListedSource(t *testing.T) {
	cfg := testConfig()
	cfg.NetFlow.AllowedSources = []string{"127.0.0.1/32"}
	cfg.SFlow.Enabled = false
	cfg.BatchSize = 1
	cfg.FlushInterval = 10 * time.Millisecond
	em := &captureEmitter{}
	c, err := New(cfg, em, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	c.decodeFn = func(_ []byte, _ string, _ time.Time) ([]Record, int, error) {
		return []Record{{Protocol: ProtoNetFlow5}}, 0, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Close()
	sendUDP(t, c.localAddr("netflow"), []byte{0x01})
	deadline := time.Now().Add(time.Second)
	for len(em.snapshot()) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("listed source did not emit; stats %+v", c.StatsSnapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := c.StatsSnapshot().SourceDrops; got != 0 {
		t.Fatalf("listed source was dropped: %+v", c.StatsSnapshot())
	}
	quality := c.qualitySnapshot(time.Now().UTC())
	if len(quality) != 1 || quality[0].ExporterAddress != "127.0.0.1" {
		t.Fatalf("listed source quality receipt = %+v", quality)
	}
}

func TestCollectorRejectsUnlistedSource(t *testing.T) {
	cfg := testConfig()
	cfg.NetFlow.AllowedSources = []string{"192.0.2.0/24"}
	cfg.SFlow.Enabled = false
	cfg.BatchSize = 1
	cfg.FlushInterval = 10 * time.Millisecond
	em := &captureEmitter{}
	c, err := New(cfg, em, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	c.decodeFn = func(_ []byte, _ string, _ time.Time) ([]Record, int, error) {
		t.Fatal("unlisted source must be dropped before decode")
		return nil, 0, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer c.Close()
	sendUDP(t, c.localAddr("netflow"), []byte{0x01})
	deadline := time.Now().Add(time.Second)
	for c.StatsSnapshot().SourceDrops == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("unlisted source was not counted as dropped; stats %+v", c.StatsSnapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := em.snapshot(); len(got) != 0 {
		t.Fatalf("unlisted source emitted records: %+v", got)
	}
	if got := c.qualitySnapshot(time.Now().UTC()); len(got) != 0 {
		t.Fatalf("unlisted source was retained in quality receipts: %+v", got)
	}
}

// TestCollectorValidation: bad configs and nil emitters are refused.
func TestCollectorValidation(t *testing.T) {
	cfg := testConfig()
	if _, err := New(cfg, nil, nil); err == nil {
		t.Error("nil emitter accepted")
	}
	cfg.TenantID = ""
	if _, err := New(cfg, &captureEmitter{}, nil); err == nil {
		t.Error("missing tenant accepted")
	}
	cfg = testConfig()
	cfg.AgentID = ""
	if _, err := New(cfg, &captureEmitter{}, nil); err == nil {
		t.Error("missing agent accepted")
	}
	cfg = testConfig()
	cfg.NetFlow.Enabled, cfg.IPFIX.Enabled, cfg.SFlow.Enabled = false, false, false
	if _, err := New(cfg, &captureEmitter{}, nil); err == nil {
		t.Error("no listeners accepted")
	}
	cfg = testConfig()
	cfg.NetFlow.Listen = ":2055"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "netflow.allowed_sources") {
		t.Fatalf("wildcard listener without source ACL must fail, got %v", err)
	}
	cfg.NetFlow.AllowedSources = []string{"10.0.0.0/8", "192.0.2.10"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("wildcard listener with source ACL must pass: %v", err)
	}
}
