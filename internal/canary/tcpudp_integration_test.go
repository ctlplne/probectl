//go:build integration

package canary_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

func TestTCPConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, e := ln.Accept()
			if e != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	c, err := canary.NewTCP(canary.Config{Type: "tcp", Target: ln.Addr().String(), Timeout: time.Second, Params: map[string]string{"count": "3"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || res.Metrics["loss.ratio"] != 0 || res.Metrics["packets.received"] != 3 {
		t.Fatalf("tcp connect: success=%v metrics=%v", res.Success, res.Metrics)
	}
	if _, ok := res.Metrics["connect.avg.ms"]; !ok {
		t.Error("missing connect.avg.ms")
	}
}

func TestTCPConnectRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // the port is now closed → connects are refused

	c, err := canary.NewTCP(canary.Config{Type: "tcp", Target: addr, Timeout: 500 * time.Millisecond, Params: map[string]string{"count": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := c.Run(context.Background())
	if res.Success || res.Metrics["loss.ratio"] != 1 {
		t.Errorf("refused connect: success=%v metrics=%v", res.Success, res.Metrics)
	}
}

func TestUDPEcho(t *testing.T) {
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

	c, err := canary.NewUDP(canary.Config{Type: "udp", Target: pc.LocalAddr().String(), Timeout: time.Second, Params: map[string]string{"count": "3"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || res.Metrics["loss.ratio"] != 0 || res.Metrics["packets.received"] != 3 {
		t.Fatalf("udp echo: success=%v metrics=%v", res.Success, res.Metrics)
	}
	if _, ok := res.Metrics["rtt.avg.ms"]; !ok {
		t.Error("missing rtt.avg.ms")
	}
}

func TestUDPNoEcho(t *testing.T) {
	// A UDP socket that drains but never replies → 100% loss.
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

	c, err := canary.NewUDP(canary.Config{Type: "udp", Target: pc.LocalAddr().String(), Timeout: 300 * time.Millisecond, Params: map[string]string{"count": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := c.Run(context.Background())
	if res.Success || res.Metrics["loss.ratio"] != 1 {
		t.Errorf("udp no-echo: success=%v metrics=%v", res.Success, res.Metrics)
	}
}
