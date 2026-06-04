package promapi

import (
	"fmt"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// WriteLimits bounds a remote-write request (untrusted input — CLAUDE.md §7
// guardrail 12). Zero values take the defaults.
type WriteLimits struct {
	MaxDecodedBytes int // after snappy decompression (decompression-bomb guard)
	MaxSeries       int // timeseries per request
	MaxSamples      int // samples per request (across series)
	MaxLabels       int // labels per series
	MaxLabelBytes   int // bytes per label name or value
}

func (l WriteLimits) withDefaults() WriteLimits {
	if l.MaxDecodedBytes <= 0 {
		l.MaxDecodedBytes = 64 << 20 // 64 MiB
	}
	if l.MaxSeries <= 0 {
		l.MaxSeries = 20000
	}
	if l.MaxSamples <= 0 {
		l.MaxSamples = 100000
	}
	if l.MaxLabels <= 0 {
		l.MaxLabels = 64
	}
	if l.MaxLabelBytes <= 0 {
		l.MaxLabelBytes = 2048
	}
	return l
}

// DecodeRemoteWrite decodes a snappy-compressed Prometheus remote-write v1
// WriteRequest into tsdb series, enforcing limits and FORCING every sample's
// tenant_id label to tenant (any caller-supplied tenant_id is overwritten —
// the payload never chooses its tenant).
func DecodeRemoteWrite(body []byte, tenant string, lim WriteLimits) ([]tsdb.Series, error) {
	lim = lim.withDefaults()
	n, err := snappy.DecodedLen(body)
	if err != nil {
		return nil, fmt.Errorf("remote-write: invalid snappy body: %v", err)
	}
	if n > lim.MaxDecodedBytes {
		return nil, fmt.Errorf("remote-write: decoded payload %d bytes exceeds limit %d", n, lim.MaxDecodedBytes)
	}
	raw, err := snappy.Decode(nil, body)
	if err != nil {
		return nil, fmt.Errorf("remote-write: snappy decode: %v", err)
	}
	var wr prompb.WriteRequest
	if err := proto.Unmarshal(raw, &wr); err != nil {
		return nil, fmt.Errorf("remote-write: protobuf decode: %v", err)
	}
	if len(wr.Timeseries) > lim.MaxSeries {
		return nil, fmt.Errorf("remote-write: %d timeseries exceeds limit %d", len(wr.Timeseries), lim.MaxSeries)
	}
	var out []tsdb.Series
	samples := 0
	for _, ts := range wr.Timeseries {
		if len(ts.Labels) > lim.MaxLabels {
			return nil, fmt.Errorf("remote-write: series has %d labels (limit %d)", len(ts.Labels), lim.MaxLabels)
		}
		metric := ""
		labels := make(map[string]string, len(ts.Labels)+1)
		for _, l := range ts.Labels {
			if len(l.Name) > lim.MaxLabelBytes || len(l.Value) > lim.MaxLabelBytes {
				return nil, fmt.Errorf("remote-write: label exceeds %d bytes", lim.MaxLabelBytes)
			}
			switch l.Name {
			case "__name__":
				metric = l.Value
			case TenantLabel:
				// dropped: the authenticated tenant is forced below
			default:
				labels[l.Name] = l.Value
			}
		}
		if metric == "" {
			return nil, fmt.Errorf("remote-write: series without __name__")
		}
		labels[TenantLabel] = tenant
		samples += len(ts.Samples)
		if samples > lim.MaxSamples {
			return nil, fmt.Errorf("remote-write: more than %d samples in one request", lim.MaxSamples)
		}
		for _, sm := range ts.Samples {
			out = append(out, tsdb.Series{
				Metric:     metric,
				Labels:     labels,
				Value:      sm.Value,
				TimeMillis: sm.Timestamp,
			})
		}
	}
	return out, nil
}
