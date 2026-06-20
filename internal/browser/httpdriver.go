// SPDX-License-Identifier: LicenseRef-probectl-TBD

package browser

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// maxArtifact bounds the captured failure-artifact body.
const maxArtifact = 1 << 20

// HTTPDriver runs a transaction at the HTTP layer (Go-native, no rendering): it
// follows the form flow with a cookie jar and captures a real per-request
// waterfall (DNS/connect/TLS/TTFB/total). On a step failure it captures the last
// response body as the artifact. Full DOM/paint timings + visual screenshots come
// from the Playwright browser driver; this driver is the lightweight default and
// the everywhere-testable one.
type HTTPDriver struct {
	transport http.RoundTripper
	guard     TargetGuard
}

// TargetGuard is the subset of canary.TargetGuard the browser driver needs.
// It is an interface to keep internal/browser independent from internal/canary.
type TargetGuard interface {
	CheckHost(host string) error
	DialControl(func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error
}

// HTTPDriverOption customizes the HTTP transaction driver.
type HTTPDriverOption func(*HTTPDriver)

// WithTargetGuard attaches the same SSRF guard used by network canaries. It is
// enforced before each request and at dial time against resolved addresses, so
// redirects and DNS rebinding cannot bypass it.
func WithTargetGuard(g TargetGuard) HTTPDriverOption {
	return func(d *HTTPDriver) {
		if g == nil {
			return
		}
		d.guard = g
		d.transport = guardedTransport(g)
	}
}

// NewHTTPDriver builds the HTTP transaction driver over a hardened (cert-
// validating) transport. The schedulable browser canary passes WithTargetGuard;
// direct package tests may use the unguarded driver against local httptest apps.
func NewHTTPDriver(opts ...HTTPDriverOption) *HTTPDriver {
	d := &HTTPDriver{transport: crypto.HardenedHTTPClient(0).Transport}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

func guardedTransport(g TargetGuard) *http.Transport {
	return &http.Transport{
		TLSClientConfig:     crypto.HardenedClientTLSConfig(),
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: (&net.Dialer{
			Control: g.DialControl(nil),
		}).DialContext,
	}
}

func (*HTTPDriver) Name() string { return "http" }

func (d *HTTPDriver) Run(ctx context.Context, s Script) (RunOutput, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: d.transport, Jar: jar}

	start := time.Now()
	form := url.Values{}
	var (
		lastBody   []byte
		lastCT     string
		lastStatus int
		haveResp   bool
		target     string // current navigation target
		firstURL   string
		steps      []StepResult
		waterfall  []ResourceTiming
		success    = true
		runErr     string
	)
	if s.StartURL != "" {
		target, firstURL = s.StartURL, s.StartURL
	}

	request := func(method, u string, body io.Reader, ct string) (StepResult, error) {
		rt, r, err := d.do(ctx, client, method, u, body, ct, start)
		waterfall = append(waterfall, rt)
		if err != nil {
			return StepResult{Success: false, Detail: err.Error()}, err
		}
		lastBody, lastCT, lastStatus, haveResp = r.body, r.contentType, r.status, true
		return StepResult{Success: true, Detail: fmt.Sprintf("%d", r.status)}, nil
	}

	for _, st := range s.Steps {
		stepStart := time.Now()
		sr := StepResult{Name: st.Name, Action: st.Action}
		var infraErr error

		switch st.Action {
		case Goto:
			if st.URL != "" {
				target = st.URL
			}
			if firstURL == "" {
				firstURL = target
			}
			r, e := request(http.MethodGet, target, nil, "")
			sr.Success, sr.Detail, infraErr = r.Success, r.Detail, e
		case Fill:
			form.Set(st.Field, st.Value)
			sr.Success, sr.Detail = true, "filled "+st.Field
		case Submit, Click:
			to := st.URL
			if to == "" {
				to = target
			}
			if firstURL == "" {
				firstURL = to
			}
			r, e := request(http.MethodPost, to, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
			form = url.Values{} // a submit consumes the accumulated form
			sr.Success, sr.Detail, infraErr = r.Success, r.Detail, e
		case AssertText, WaitText:
			sr.Success = haveResp && strings.Contains(string(lastBody), st.Value)
			if sr.Success {
				sr.Detail = "found"
			} else {
				sr.Detail = fmt.Sprintf("text %q not found", st.Value)
			}
		case AssertStatus:
			sr.Success = haveResp && lastStatus == st.Status
			sr.Detail = fmt.Sprintf("status %d (want %d)", lastStatus, st.Status)
		case Screenshot:
			sr.Success = true
			sr.Detail = "captured"
		}

		sr.DurationMs = time.Since(stepStart).Milliseconds()
		steps = append(steps, sr)

		if infraErr != nil {
			// An infrastructure fault (DNS/connect/TLS): fail the run + recycle.
			success = false
			runErr = fmt.Sprintf("step %q (%s): %s", st.Name, st.Action, infraErr)
			out := d.result(s, firstURL, success, runErr, start, steps, waterfall)
			return RunOutput{Result: out, Screenshot: artifact(lastBody), ScreenshotType: artifactType(lastCT)},
				infraErr
		}
		if !sr.Success && !st.Optional {
			success = false
			runErr = fmt.Sprintf("step %q (%s): %s", st.Name, st.Action, sr.Detail)
			break
		}
	}

	out := d.result(s, firstURL, success, runErr, start, steps, waterfall)
	var shot []byte
	var sct string
	if !success {
		shot, sct = artifact(lastBody), artifactType(lastCT)
	}
	return RunOutput{Result: out, Screenshot: shot, ScreenshotType: sct}, nil
}

func (*HTTPDriver) result(s Script, target string, ok bool, errMsg string, start time.Time, steps []StepResult, wf []ResourceTiming) Result {
	return Result{
		Script: s.Name, Target: target, Success: ok, Error: errMsg,
		StartedAt: start, TotalMs: time.Since(start).Milliseconds(),
		Steps: steps, Waterfall: wf,
	}
}

// httpResp is the extracted, body-closed response do returns — the *http.Response
// never escapes do, so its body is always closed here.
type httpResp struct {
	status      int
	contentType string
	body        []byte
}

// do performs one request, capturing a resource-timing entry via httptrace. It
// reads + closes the response body before returning (nothing leaks).
func (d *HTTPDriver) do(ctx context.Context, client *http.Client, method, rawURL string, body io.Reader, ct string, txStart time.Time) (ResourceTiming, httpResp, error) {
	rt := ResourceTiming{Method: method}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return rt, httpResp{}, err
	}
	rt.URL = req.URL.String()
	if d.guard != nil {
		if err := d.guard.CheckHost(req.URL.Hostname()); err != nil {
			return rt, httpResp{}, err
		}
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("User-Agent", "probectl-browser-synthetic")

	var dnsStart, connStart, tlsStart time.Time
	reqStart := time.Now()
	// Note: TLSHandshakeDone's callback takes a tls.ConnectionState, but importing
	// crypto/tls outside internal/crypto trips the FIPS guard — so the TLS phase is
	// measured from TLSHandshakeStart to GotConn (when the connection, post-
	// handshake, is obtained), which needs no crypto/tls reference.
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { rt.DNSms = sinceMs(dnsStart) },
		ConnectStart:      func(string, string) { connStart = time.Now() },
		ConnectDone:       func(string, string, error) { rt.ConnectMs = sinceMs(connStart) },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		GotConn: func(httptrace.GotConnInfo) {
			if !tlsStart.IsZero() {
				rt.TLSms = sinceMs(tlsStart)
			}
		},
		GotFirstResponseByte: func() { rt.TTFBms = time.Since(reqStart).Milliseconds() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	rt.StartMs = reqStart.Sub(txStart).Milliseconds()

	resp, err := client.Do(req)
	if err != nil {
		rt.TotalMs = time.Since(reqStart).Milliseconds()
		return rt, httpResp{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxArtifact))
	rt.TotalMs = time.Since(reqStart).Milliseconds()
	rt.Status = resp.StatusCode
	rt.SizeBytes = int64(len(b))
	return rt, httpResp{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), body: b}, nil
}

func sinceMs(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return time.Since(t).Milliseconds()
}

func artifact(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	cp := make([]byte, len(body))
	copy(cp, body)
	return cp
}

func artifactType(ct string) string {
	if ct == "" {
		return "text/html"
	}
	return ct
}
