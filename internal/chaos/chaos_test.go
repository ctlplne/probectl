package chaos

import (
	"context"
	"net"
	"testing"
	"time"
)

func echoServer(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc
}

func startProxy(t *testing.T, target string, f Fault) *UDPProxy {
	t.Helper()
	p, err := NewUDPProxy(target, f)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Run(ctx) }()
	return p
}

// roundTrip sends one datagram through the proxy and waits for the echo.
func roundTrip(t *testing.T, addr string, timeout time.Duration) (time.Duration, bool) {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(start.Add(timeout))
	buf := make([]byte, 32)
	if _, err := conn.Read(buf); err != nil {
		return 0, false
	}
	return time.Since(start), true
}

func TestFaultValidation(t *testing.T) {
	for name, f := range map[string]Fault{
		"negative latency": {LatencyMs: -1},
		"absurd latency":   {LatencyMs: 120_000},
		"loss over 100":    {LossPct: 120},
		"negative loss":    {LossPct: -5},
	} {
		if err := f.Validate(); err == nil {
			t.Errorf("%s must fail validation", name)
		}
	}
	if err := (Fault{LatencyMs: 200, JitterMs: 50, LossPct: 30}).Validate(); err != nil {
		t.Errorf("sane fault rejected: %v", err)
	}
	if _, err := NewUDPProxy("127.0.0.1:9", Fault{LossPct: 200}); err == nil {
		t.Error("proxy must reject an invalid initial fault (fail closed)")
	}
}

func TestProxyPassThroughHealthy(t *testing.T) {
	echo := echoServer(t)
	p := startProxy(t, echo.LocalAddr().String(), Fault{})
	rtt, ok := roundTrip(t, p.Addr(), time.Second)
	if !ok {
		t.Fatal("healthy proxy must echo")
	}
	if rtt > 200*time.Millisecond {
		t.Errorf("no-fault proxy added %v", rtt)
	}
}

func TestProxyInjectsLatency(t *testing.T) {
	echo := echoServer(t)
	p := startProxy(t, echo.LocalAddr().String(), Fault{LatencyMs: 80})
	rtt, ok := roundTrip(t, p.Addr(), 2*time.Second)
	if !ok {
		t.Fatal("latency fault must still deliver")
	}
	// 80ms applied per direction → ≥160ms on the round trip.
	if rtt < 160*time.Millisecond {
		t.Errorf("round trip %v want ≥ 160ms (80ms per direction)", rtt)
	}
}

func TestProxyPartitionDropsEverything(t *testing.T) {
	echo := echoServer(t)
	p := startProxy(t, echo.LocalAddr().String(), Fault{Partition: true})
	if _, ok := roundTrip(t, p.Addr(), 300*time.Millisecond); ok {
		t.Fatal("partition must blackhole")
	}
	// Heal the partition mid-run: traffic flows again (the chaos-run shape).
	if err := p.SetFault(Fault{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := roundTrip(t, p.Addr(), time.Second); !ok {
		t.Fatal("healed proxy must echo again")
	}
}

func TestProxyAppliesLossProbabilistically(t *testing.T) {
	echo := echoServer(t)
	p := startProxy(t, echo.LocalAddr().String(), Fault{LossPct: 50})
	lost, got := 0, 0
	for i := 0; i < 60; i++ {
		if _, ok := roundTrip(t, p.Addr(), 150*time.Millisecond); ok {
			got++
		} else {
			lost++
		}
	}
	// 50% per direction ≈ 75% round-trip loss; accept a broad band — this
	// asserts the dice are rolling, not a calibrated distribution.
	if lost < 20 || got == 0 {
		t.Errorf("50%% loss fault: lost=%d got=%d — fault not applying", lost, got)
	}
	if err := p.SetFault(Fault{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := roundTrip(t, p.Addr(), time.Second); !ok {
		t.Fatal("cleared loss must echo reliably again")
	}
}

func TestSetFaultRejectsInvalidKeepsPrevious(t *testing.T) {
	echo := echoServer(t)
	p := startProxy(t, echo.LocalAddr().String(), Fault{})
	if err := p.SetFault(Fault{LossPct: 999}); err == nil {
		t.Fatal("invalid fault must be rejected")
	}
	if _, ok := roundTrip(t, p.Addr(), time.Second); !ok {
		t.Fatal("previous (healthy) fault must remain active")
	}
}
