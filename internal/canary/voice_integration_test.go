//go:build integration

package canary_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

// The S47c 'Done when': a voice test reports MOS, jitter, and loss.
func TestVoiceRTPEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()

	c, err := canary.NewVoice(canary.Config{
		Type: "voice", Target: pc.LocalAddr().String(), Timeout: time.Second,
		Params: map[string]string{"allow_private_targets": "true", "duration_seconds": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("voice echo failed: %v %v", res.Error, res.Metrics)
	}
	// The contract fields: MOS + R + jitter + loss + one-way estimate.
	mos := res.Metrics["voice.mos"]
	if mos < 4.0 || mos > 4.5 {
		t.Errorf("loopback clean call: mos = %v want ~4.3-4.4", mos)
	}
	if res.Metrics["voice.r_factor"] <= 0 {
		t.Error("missing voice.r_factor")
	}
	if _, ok := res.Metrics["voice.jitter.ms"]; !ok {
		t.Error("missing voice.jitter.ms")
	}
	if res.Metrics["voice.loss.pct"] != 0 {
		t.Errorf("loopback loss = %v want 0", res.Metrics["voice.loss.pct"])
	}
	if res.Metrics["packets.sent"] != 50 { // 1s of g711 at 20ms frames
		t.Errorf("packets.sent = %v want 50", res.Metrics["packets.sent"])
	}
	// Model honesty rides the attributes.
	if res.Attributes["voice.model"] == "" || res.Attributes["voice.codec"] != "g711" {
		t.Errorf("model/codec attributes missing: %+v", res.Attributes)
	}
}

// A lossy reflector (drops every 4th packet) must crater the MOS vs clean.
func TestVoiceRTPLossDegradesMOS(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	var n64 atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			if n64.Add(1)%4 == 0 {
				continue // drop every 4th — 25% loss
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()

	c, err := canary.NewVoice(canary.Config{
		Type: "voice", Target: pc.LocalAddr().String(), Timeout: time.Second,
		Params: map[string]string{"allow_private_targets": "true", "duration_seconds": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("lossy call still has echoes: %v", res.Error)
	}
	loss := res.Metrics["voice.loss.pct"]
	if loss < 15 || loss > 35 {
		t.Errorf("loss = %v want ~25", loss)
	}
	if mos := res.Metrics["voice.mos"]; mos > 3.2 {
		t.Errorf("25%% loss must crater MOS, got %v", mos)
	}
}

// A black-holing target is an unmeasurable voice path: honest failure.
func TestVoiceNoEcho(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			if _, _, e := pc.ReadFrom(buf); e != nil {
				return
			}
		}
	}()

	c, err := canary.NewVoice(canary.Config{
		Type: "voice", Target: pc.LocalAddr().String(), Timeout: 300 * time.Millisecond,
		Params: map[string]string{"allow_private_targets": "true", "duration_seconds": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := c.Run(context.Background())
	if res.Success || res.Metrics["loss.ratio"] != 1 {
		t.Errorf("no-echo: success=%v metrics=%v", res.Success, res.Metrics)
	}
	if _, ok := res.Metrics["voice.mos"]; ok {
		t.Error("an unmeasurable path must NOT report a fabricated MOS")
	}
}
