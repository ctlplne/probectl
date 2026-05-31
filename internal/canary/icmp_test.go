package canary

import (
	"testing"
	"time"

	"golang.org/x/net/icmp"
)

func ms(x float64) time.Duration { return time.Duration(x * float64(time.Millisecond)) }

func approx(a, b, eps float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= eps
}

func TestComputeICMPStats(t *testing.T) {
	tests := []struct {
		name                                           string
		rtts                                           []time.Duration
		sent                                           int
		wantRecv                                       int
		wantLoss                                       float64
		wantMin, wantAvg, wantMax, wantStddev, wantJit float64
	}{
		{"all equal", []time.Duration{ms(10), ms(10), ms(10)}, 3, 3, 0, 10, 10, 10, 0, 0},
		{"varied", []time.Duration{ms(10), ms(20), ms(30)}, 3, 3, 0, 10, 20, 30, 8.16497, 10},
		{"partial loss", []time.Duration{ms(10), -1, ms(30)}, 3, 2, 1.0 / 3.0, 10, 20, 30, 10, 20},
		{"total loss", []time.Duration{-1, -1}, 2, 0, 1, 0, 0, 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := computeICMPStats(tt.rtts, tt.sent)
			if s.Sent != tt.sent || s.Received != tt.wantRecv {
				t.Fatalf("sent/received = %d/%d, want %d/%d", s.Sent, s.Received, tt.sent, tt.wantRecv)
			}
			if !approx(s.LossRatio, tt.wantLoss, 1e-9) {
				t.Errorf("loss = %v, want %v", s.LossRatio, tt.wantLoss)
			}
			if tt.wantRecv == 0 {
				return
			}
			if !approx(s.MinMs, tt.wantMin, 1e-5) || !approx(s.AvgMs, tt.wantAvg, 1e-5) || !approx(s.MaxMs, tt.wantMax, 1e-5) {
				t.Errorf("min/avg/max = %v/%v/%v, want %v/%v/%v", s.MinMs, s.AvgMs, s.MaxMs, tt.wantMin, tt.wantAvg, tt.wantMax)
			}
			if !approx(s.StddevMs, tt.wantStddev, 1e-4) {
				t.Errorf("stddev = %v, want %v", s.StddevMs, tt.wantStddev)
			}
			if !approx(s.JitterMs, tt.wantJit, 1e-5) {
				t.Errorf("jitter = %v, want %v", s.JitterMs, tt.wantJit)
			}
		})
	}
}

func TestICMPStatsMetrics(t *testing.T) {
	// With replies, all rtt + loss keys are present.
	full := computeICMPStats([]time.Duration{ms(10), ms(20)}, 2).metrics()
	for _, k := range []string{"loss.ratio", "packets.sent", "packets.received", "rtt.min.ms", "rtt.avg.ms", "rtt.max.ms", "rtt.stddev.ms", "jitter.ms"} {
		if _, ok := full[k]; !ok {
			t.Errorf("missing metric %q", k)
		}
	}
	// Total loss omits rtt metrics but still reports loss + counts.
	lost := computeICMPStats([]time.Duration{-1, -1}, 2).metrics()
	if lost["loss.ratio"] != 1 || lost["packets.received"] != 0 {
		t.Errorf("total-loss metrics = %v", lost)
	}
	if _, ok := lost["rtt.avg.ms"]; ok {
		t.Error("rtt.avg.ms should be absent when nothing was received")
	}
}

func TestDropRecord(t *testing.T) {
	rtts := []time.Duration{ms(10), -1, ms(30), -1}
	offs := []time.Duration{0, time.Second, 2 * time.Second, 3 * time.Second}
	seqs, offStr := dropRecord(rtts, offs)
	if seqs != "1,3" || offStr != "1000,3000" {
		t.Errorf("dropRecord = %q / %q, want 1,3 / 1000,3000", seqs, offStr)
	}
	if s, o := dropRecord([]time.Duration{ms(1), ms(1)}, []time.Duration{0, 0}); s != "" || o != "" {
		t.Errorf("no-drop record = %q / %q, want empty", s, o)
	}
}

func TestNewICMPParams(t *testing.T) {
	if _, err := NewICMP(Config{Type: "icmp"}); err == nil {
		t.Error("missing target should error")
	}

	got, err := NewICMP(Config{Type: "icmp", Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c := got.(*icmpCanary)
	if c.count != 5 || c.payload != 56 || c.continuous || c.timeout != 3*time.Second {
		t.Errorf("defaults wrong: %+v", c)
	}

	got, err = NewICMP(Config{Type: "icmp", Target: "h", Interval: 8 * time.Second, Params: map[string]string{
		"payload_bytes": "100", "dscp": "46", "mode": "continuous",
	}})
	if err != nil {
		t.Fatal(err)
	}
	c = got.(*icmpCanary)
	if !c.continuous || c.spacing != time.Second || c.count != 8 || c.payload != 100 || c.dscp != 46 {
		t.Errorf("continuous config wrong: %+v", c)
	}

	for _, bad := range []map[string]string{
		{"count": "0"}, {"payload_bytes": "4"}, {"dscp": "64"}, {"count": "x"}, {"mode": "weird"},
	} {
		if _, err := NewICMP(Config{Type: "icmp", Target: "h", Params: bad}); err == nil {
			t.Errorf("params %v should be rejected", bad)
		}
	}
}

func TestBuildEchoRoundTrip(t *testing.T) {
	token := []byte("TOKEN123")
	raw, err := buildEcho(false, 0x1234, 7, token, 56)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := icmp.ParseMessage(ianaProtoICMP, raw)
	if err != nil {
		t.Fatal(err)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("body is %T, want *icmp.Echo", msg.Body)
	}
	if echo.Seq != 7 || echo.ID != 0x1234 {
		t.Errorf("seq/id = %d/%d, want 7/4660", echo.Seq, echo.ID)
	}
	if len(echo.Data) != 56 || string(echo.Data[:len(token)]) != string(token) {
		t.Errorf("payload mismatch: len=%d prefix=%q", len(echo.Data), echo.Data[:len(token)])
	}
}
