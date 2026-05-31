package canary

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// icmpStats is the aggregated outcome of one ICMP echo batch.
type icmpStats struct {
	Sent, Received                          int
	LossRatio                               float64
	MinMs, AvgMs, MaxMs, StddevMs, JitterMs float64
}

// computeICMPStats aggregates per-sequence RTTs into loss/latency/jitter. rtts is
// indexed by send order; a negative entry means that sequence got no reply
// (lost). Latency stats and jitter are computed over the replies that arrived,
// in send order. Jitter is the mean absolute difference between consecutive
// received RTTs (a standard, resolver-independent definition).
func computeICMPStats(rtts []time.Duration, sent int) icmpStats {
	received := make([]float64, 0, len(rtts))
	for _, d := range rtts {
		if d >= 0 {
			received = append(received, float64(d)/float64(time.Millisecond))
		}
	}

	s := icmpStats{Sent: sent, Received: len(received)}
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

// metrics renders the stats as the result metric map. Names follow the
// `dotted.path` convention; the pipeline maps them to netctl_probe_<name>.
func (s icmpStats) metrics() map[string]float64 {
	m := map[string]float64{
		"loss.ratio":       round(s.LossRatio, 4),
		"packets.sent":     float64(s.Sent),
		"packets.received": float64(s.Received),
	}
	if s.Received > 0 {
		m["rtt.min.ms"] = round(s.MinMs, 3)
		m["rtt.avg.ms"] = round(s.AvgMs, 3)
		m["rtt.max.ms"] = round(s.MaxMs, 3)
		m["rtt.stddev.ms"] = round(s.StddevMs, 3)
		m["jitter.ms"] = round(s.JitterMs, 3)
	}
	return m
}

// dropRecord builds the continuous-mode drop-timing record: the comma-separated
// sequence numbers that were lost and each one's send offset (ms from the start
// of the probe). Both are empty when nothing was dropped.
func dropRecord(rtts []time.Duration, sendOffsets []time.Duration) (seqs, offsetsMs string) {
	var sb, ob strings.Builder
	for i, d := range rtts {
		if d >= 0 {
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(',')
			ob.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(i))
		ob.WriteString(strconv.FormatInt(sendOffsets[i].Milliseconds(), 10))
	}
	return sb.String(), ob.String()
}

// round rounds v to n decimal places (keeps metric values tidy).
func round(v float64, n int) float64 {
	p := math.Pow10(n)
	return math.Round(v*p) / p
}
