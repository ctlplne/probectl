package tsdb

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
)

// Prometheus writes series via the Prometheus remote-write protocol (a snappy-
// compressed protobuf POSTed to <url>/api/v1/write). It targets Prometheus (run
// with --web.enable-remote-write-receiver) and VictoriaMetrics. TLS in transit is
// supported by using an https URL (CLAUDE.md §7 guardrail 12).
type Prometheus struct {
	url    string
	client *http.Client
}

// NewPrometheus returns a remote-write writer targeting the base URL (e.g.
// http://localhost:9090).
func NewPrometheus(url string) *Prometheus {
	return &Prometheus{
		url:    strings.TrimRight(url, "/") + "/api/v1/write",
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// Write remote-writes the series.
func (p *Prometheus) Write(ctx context.Context, series []Series) error {
	if len(series) == 0 {
		return nil
	}
	wr := &prompb.WriteRequest{}
	for _, s := range series {
		labels := []*prompb.Label{{Name: "__name__", Value: s.Metric}}
		for k, v := range s.Labels {
			labels = append(labels, &prompb.Label{Name: k, Value: v})
		}
		// Prometheus remote-write expects labels sorted by name.
		sort.Slice(labels, func(i, j int) bool { return labels[i].GetName() < labels[j].GetName() })
		wr.Timeseries = append(wr.Timeseries, &prompb.TimeSeries{
			Labels:  labels,
			Samples: []*prompb.Sample{{Value: s.Value, Timestamp: s.TimeMillis}},
		})
	}

	raw, err := proto.Marshal(wr)
	if err != nil {
		return fmt.Errorf("tsdb: marshal write request: %w", err)
	}
	compressed := snappy.Encode(nil, raw)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(compressed))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("tsdb: remote-write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("tsdb: remote-write status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// Close is a no-op.
func (p *Prometheus) Close() error { return nil }
