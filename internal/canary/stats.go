package canary

import (
	"math"
	"time"
)

// latencyStats aggregates a set of probe latency samples into loss plus
// min/avg/max/stddev/jitter. It is shared by the latency-style canaries
// (icmp/tcp/udp) so the math is defined and tested once.
type latencyStats struct {
	Sent, Received                          int
	LossRatio                               float64
	MinMs, AvgMs, MaxMs, StddevMs, JitterMs float64
}

// computeLatencyStats aggregates per-probe samples (indexed by send order; a
// negative entry means that probe got no reply) over the replies that arrived.
// Jitter is the mean absolute difference between consecutive received samples (a
// standard, target-independent definition).
func computeLatencyStats(samples []time.Duration, sent int) latencyStats {
	received := make([]float64, 0, len(samples))
	for _, d := range samples {
		if d >= 0 {
			received = append(received, float64(d)/float64(time.Millisecond))
		}
	}

	s := latencyStats{Sent: sent, Received: len(received)}
	if sent > 0 {
		s.LossRatio = float64(sent-len(received)) / float64(sent)
	}
	if len(received) == 0 {
		return s
	}

	sum, mn, mx := 0.0, received[0], received[0]
	for _, v := range received {
		sum += v
		mn = math.Min(mn, v)
		mx = math.Max(mx, v)
	}
	s.MinMs, s.MaxMs, s.AvgMs = mn, mx, sum/float64(len(received))

	var sq float64
	for _, v := range received {
		d := v - s.AvgMs
		sq += d * d
	}
	s.StddevMs = math.Sqrt(sq / float64(len(received)))

	if len(received) > 1 {
		var j float64
		for i := 1; i < len(received); i++ {
			j += math.Abs(received[i] - received[i-1])
		}
		s.JitterMs = j / float64(len(received)-1)
	}
	return s
}

// latencyMetrics renders loss + the latency family (named e.g. "rtt" or
// "connect") plus probe counts as the result metric map. Names follow the
// dotted-path convention; the pipeline maps them to probectl_probe_<name>.
func (s latencyStats) latencyMetrics(name string) map[string]float64 {
	m := map[string]float64{
		"loss.ratio":       round(s.LossRatio, 4),
		"packets.sent":     float64(s.Sent),
		"packets.received": float64(s.Received),
	}
	if s.Received > 0 {
		m[name+".min.ms"] = round(s.MinMs, 3)
		m[name+".avg.ms"] = round(s.AvgMs, 3)
		m[name+".max.ms"] = round(s.MaxMs, 3)
		m[name+".stddev.ms"] = round(s.StddevMs, 3)
		m["jitter.ms"] = round(s.JitterMs, 3)
	}
	return m
}

// round rounds v to n decimal places (keeps metric values tidy).
func round(v float64, n int) float64 {
	p := math.Pow10(n)
	return math.Round(v*p) / p
}
