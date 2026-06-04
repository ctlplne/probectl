package promapi

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Upstream forwards CANONICAL (parsed, tenant-forced, reconstructed) selector
// queries to the backing Prometheus/VictoriaMetrics when probectl runs in
// tsdb=prometheus mode. Raw caller input is never forwarded — only
// Selector.String() reconstructions (see package doc). Responses are already
// Prometheus-API JSON and pass through verbatim.
type Upstream struct {
	base   string
	client *http.Client
}

// NewUpstream returns a proxy to the TSDB base URL (e.g. http://victoria:8428).
// TLS certificates are validated when the URL is https (guardrail 12).
func NewUpstream(baseURL string) *Upstream {
	return &Upstream{
		base:   strings.TrimRight(baseURL, "/"),
		client: crypto.HardenedHTTPClient(30 * time.Second),
	}
}

// Result is a passthrough upstream response.
type Result struct {
	Status      int
	ContentType string
	Body        []byte
}

func (u *Upstream) get(ctx context.Context, path string, params url.Values) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.base+path+"?"+params.Encode(), nil)
	if err != nil {
		return Result{}, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("upstream tsdb: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return Result{}, fmt.Errorf("upstream tsdb read: %w", err)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	return Result{Status: resp.StatusCode, ContentType: ct, Body: body}, nil
}

// QueryInstant forwards an instant query for sel at time at.
func (u *Upstream) QueryInstant(ctx context.Context, sel Selector, at time.Time) (Result, error) {
	p := url.Values{}
	p.Set("query", sel.String())
	p.Set("time", formatTime(at))
	return u.get(ctx, "/api/v1/query", p)
}

// QueryRange forwards a range query for sel over [start, end] at step.
func (u *Upstream) QueryRange(ctx context.Context, sel Selector, start, end time.Time, step string) (Result, error) {
	p := url.Values{}
	p.Set("query", sel.String())
	p.Set("start", formatTime(start))
	p.Set("end", formatTime(end))
	if step == "" {
		step = "15s"
	}
	p.Set("step", step)
	return u.get(ctx, "/api/v1/query_range", p)
}

// Series forwards a series-metadata query.
func (u *Upstream) Series(ctx context.Context, sels []Selector, start, end time.Time) (Result, error) {
	p := url.Values{}
	for _, sel := range sels {
		p.Add("match[]", sel.String())
	}
	p.Set("start", formatTime(start))
	p.Set("end", formatTime(end))
	return u.get(ctx, "/api/v1/series", p)
}

// LabelNames forwards a label-names query scoped by sels.
func (u *Upstream) LabelNames(ctx context.Context, sels []Selector, start, end time.Time) (Result, error) {
	p := url.Values{}
	for _, sel := range sels {
		p.Add("match[]", sel.String())
	}
	p.Set("start", formatTime(start))
	p.Set("end", formatTime(end))
	return u.get(ctx, "/api/v1/labels", p)
}

// LabelValues forwards a label-values query for name scoped by sels.
func (u *Upstream) LabelValues(ctx context.Context, name string, sels []Selector, start, end time.Time) (Result, error) {
	p := url.Values{}
	for _, sel := range sels {
		p.Add("match[]", sel.String())
	}
	p.Set("start", formatTime(start))
	p.Set("end", formatTime(end))
	return u.get(ctx, "/api/v1/label/"+url.PathEscape(name)+"/values", p)
}

func formatTime(t time.Time) string {
	return fmt.Sprintf("%.3f", float64(t.UnixMilli())/1000.0)
}
