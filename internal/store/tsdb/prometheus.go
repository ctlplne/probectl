// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"sync/atomic"
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
	url               string
	client            *http.Client
	breaker           *breaker.Breaker
	rejectedPermanent atomic.Uint64 // samples remote-write rejected with a 4xx (CORRECT-003)
}

// ErrPermanentReject marks a remote-write rejection the server will NEVER
// accept on retry: a 4xx status. By far the most common cause is a sample that
// is out-of-order or older than the TSDB's out-of-order ingestion window
// (Prometheus rejects these with HTTP 400). Retrying such a sample only burns
// the backoff budget and delays the DLQ, so the pipeline retry loops treat it
// as permanent and dead-letter it immediately rather than retrying (CORRECT-003).
//
// To let legitimately-late samples (store-and-forward backlog drains after an
// agent reconnects) actually land instead of being rejected, widen the
// receiver's out-of-order window: Prometheus `tsdb.out_of_order_time_window`
// (>=0; we recommend at least the max store-and-forward buffer horizon) or
// VictoriaMetrics `-search.maxStalenessInterval` / `-dedup.minScrapeInterval`.
// See docs/configuration.md and docs/ops/tsdb.md.
var ErrPermanentReject = errors.New("tsdb: remote-write permanently rejected (4xx; out-of-order or too-old sample, or malformed request)")

// RejectedPermanent reports the cumulative count of samples the upstream
// remote-write endpoint rejected with a 4xx (CORRECT-003 observability).
func (p *Prometheus) RejectedPermanent() uint64 { return p.rejectedPermanent.Load() }

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
		r, e := p.client.Do(req) //nolint:bodyclose // the response escapes to promDo's caller, which closes it
		if e != nil {
			return e
		}
		resp = r
		// RESIL-005: an up-but-erroring upstream (5xx/429) is a breaker fault
		// too, not just a transport error. Count it (sentinel) but still
		// surface the response; the sentinel is stripped below.
		if r.StatusCode >= 500 || r.StatusCode == http.StatusTooManyRequests {
			return errServerError
		}
		return nil
	})
	if errors.Is(err, errServerError) {
		err = nil
	}
	return resp, err
}

// errServerError marks a completed-but-faulting (5xx/429) response as a breaker
// failure while letting the response escape to the caller (RESIL-005).
var errServerError = errors.New("tsdb: upstream server error (5xx/429)")

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

// LabeledSample is one series of an instant-vector query result: its label set
// and current value.
type LabeledSample struct {
	Labels map[string]string
	Value  float64
}

// InstantVector runs an instant PromQL query and returns one LabeledSample per
// matching series. It is the read path the alert evaluator needs in the
// production (remote-write) profile, where the in-memory TSDB is absent and
// rules would otherwise never evaluate (ARCH-002/CORRECT-006). The caller is
// responsible for pinning the query to a tenant (the alert metricSource does).
func (p *Prometheus) InstantVector(ctx context.Context, promql string) ([]LabeledSample, error) {
	base := strings.TrimSuffix(p.url, "/api/v1/write")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query?query="+url.QueryEscape(promql), nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.promDo(req)
	if err != nil {
		return nil, fmt.Errorf("tsdb: instant query: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsdb: instant query status %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Data struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  []any             `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("tsdb: instant query decode: %w", err)
	}
	samples := make([]LabeledSample, 0, len(out.Data.Result))
	for _, r := range out.Data.Result {
		if len(r.Value) < 2 {
			continue
		}
		str, _ := r.Value[1].(string)
		v, perr := strconv.ParseFloat(str, 64)
		if perr != nil {
			continue
		}
		samples = append(samples, LabeledSample{Labels: r.Metric, Value: v})
	}
	return samples, nil
}

// Write remote-writes tenant-owned series.
func (p *Prometheus) Write(ctx context.Context, series []Series) error {
	if err := ValidateTenantSeries(series); err != nil {
		return err
	}
	return p.write(ctx, series)
}

// WriteGlobal remote-writes explicit non-tenant control-plane metrics.
func (p *Prometheus) WriteGlobal(ctx context.Context, series []Series) error {
	if err := ValidateGlobalSeries(series); err != nil {
		return err
	}
	return p.write(ctx, series)
}

func (p *Prometheus) write(ctx context.Context, series []Series) error {
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
		// CORRECT-003: a 4xx is the server saying "I will never accept this" —
		// almost always an out-of-order / too-old sample. Mark it permanent so
		// the retry loop dead-letters it immediately instead of retrying (which
		// can never succeed). 5xx / network errors stay transient (retryable).
		if resp.StatusCode/100 == 4 {
			p.rejectedPermanent.Add(1)
			return fmt.Errorf("tsdb: remote-write status %d: %s: %w", resp.StatusCode, body, ErrPermanentReject)
		}
		return fmt.Errorf("tsdb: remote-write status %d: %s", resp.StatusCode, body)
	}
	return nil
}

// Close is a no-op.
func (p *Prometheus) Close() error { return nil }
