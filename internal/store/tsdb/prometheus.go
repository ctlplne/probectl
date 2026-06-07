package tsdb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	prompb "github.com/imfeelingtheagi/probectl/internal/gen/prometheus/v1"
)

// Prometheus writes series via the Prometheus remote-write protocol (a snappy-
// compressed protobuf POSTed to <url>/api/v1/write). It targets Prometheus (run
// with --web.enable-remote-write-receiver) and VictoriaMetrics. TLS in transit is
// supported by using an https URL (CLAUDE.md §7 guardrail 12).
type Prometheus struct {
	url     string
	client  *http.Client
	breaker *breaker.Breaker
}

// NewPrometheus returns a remote-write writer targeting the base URL (e.g.
// http://localhost:9090). Egress uses the hardened TLS client (U-036): an
// https endpoint gets the TLS 1.2+/AEAD-only/always-verified policy from
// internal/crypto; a plain-http loopback dev endpoint is unaffected. A circuit
// breaker (U-078) short-circuits when the upstream is down.
func NewPrometheus(url string) *Prometheus {
	return &Prometheus{
		url:     strings.TrimRight(url, "/") + "/api/v1/write",
		client:  crypto.HardenedHTTPClient(30 * time.Second),
		breaker: breaker.New(0, 0),
	}
}

// promDo issues the request through the circuit breaker (U-078): a transport
// failure (upstream unreachable) trips it after the threshold, short-circuiting
// further calls until a cooldown probe succeeds.
func (p *Prometheus) promDo(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	err := p.breaker.Do(func() error {
		r, e := p.client.Do(req)
		if e != nil {
			return e
		}
		resp = r
		return nil
	})
	return resp, err
}

// BreakerStats exposes the TSDB breaker state (U-078 fallback metrics).
func (p *Prometheus) BreakerStats() breaker.Stats { return p.breaker.Stats() }

// ErrAdminAPIDisabled reports that the upstream's admin API (delete_series)
// is not enabled — the erasure engine then records the documented manual
// step instead (U-027 honest fallback).
var ErrAdminAPIDisabled = errors.New("tsdb: prometheus admin API unavailable (run with --web.enable-admin-api to automate series deletion)")

// DeleteTenant removes every series labeled with the tenant via the
// Prometheus/VictoriaMetrics admin API (delete_series + clean_tombstones),
// then verifies via an instant query that zero series remain. The series
// count is not reported by the API, so the return is 0 with verification
// carried by the error result (U-027).
func (p *Prometheus) DeleteTenant(ctx context.Context, tenantID string) (int, error) {
	base := strings.TrimSuffix(p.url, "/api/v1/write")
	matcher := url.QueryEscape(`{tenant_id="` + tenantID + `"}`)

	del, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v1/admin/tsdb/delete_series?match[]="+matcher, nil)
	if err != nil {
		return 0, err
	}
	resp, err := p.client.Do(del)
	if err != nil {
		return 0, fmt.Errorf("tsdb: delete_series: %w", err)
	}
	_ = resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusForbidden, http.StatusUnauthorized:
		return 0, ErrAdminAPIDisabled
	default:
		return 0, fmt.Errorf("tsdb: delete_series returned %d", resp.StatusCode)
	}

	// Best-effort tombstone clean (VictoriaMetrics deletes immediately and
	// has no such endpoint — non-2xx here is not a failure).
	if clean, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/api/v1/admin/tsdb/clean_tombstones", nil); err == nil {
		if r2, err := p.client.Do(clean); err == nil {
			_ = r2.Body.Close()
		}
	}

	// Verify: an instant query for the tenant must return no series.
	q, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query?query="+url.QueryEscape(`count({tenant_id="`+tenantID+`"})`), nil)
	if err != nil {
		return 0, err
	}
	r3, err := p.client.Do(q)
	if err != nil {
		return 0, fmt.Errorf("tsdb: post-delete verification query: %w", err)
	}
	defer r3.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r3.Body, 1<<20))
	var out struct {
		Data struct {
			Result []any `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, fmt.Errorf("tsdb: verification decode: %w", err)
	}
	if len(out.Data.Result) != 0 {
		return 0, fmt.Errorf("tsdb: series remain after delete_series (verification failed)")
	}
	return 0, nil
}

// Count runs an instant PromQL query and returns its single scalar/vector
// value (0 when the result is empty). The full-stack load gate (U-005) uses
// it to confirm ingested series and to time tenant-scoped queries.
func (p *Prometheus) Count(ctx context.Context, promql string) (float64, error) {
	base := strings.TrimSuffix(p.url, "/api/v1/write")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query?query="+url.QueryEscape(promql), nil)
	if err != nil {
		return 0, err
	}
	resp, err := p.promDo(req)
	if err != nil {
		return 0, fmt.Errorf("tsdb: instant query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("tsdb: instant query status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Data struct {
			Result []struct {
				Value []any `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, fmt.Errorf("tsdb: instant query decode: %w", err)
	}
	if len(out.Data.Result) == 0 || len(out.Data.Result[0].Value) < 2 {
		return 0, nil
	}
	str, _ := out.Data.Result[0].Value[1].(string)
	v, err := strconv.ParseFloat(str, 64)
	if err != nil {
		return 0, fmt.Errorf("tsdb: instant query value %q: %w", str, err)
	}
	return v, nil
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

	resp, err := p.promDo(req)
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
