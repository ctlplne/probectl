// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// The sub-collectors are injected so the orchestration is testable with fakes and
// the platform-specific exec lives behind a narrow seam. A collector returns its
// best-effort reading; an error means "unavailable", never a panic.
type (
	// WiFiCollector reads the local wireless link.
	WiFiCollector interface {
		Collect(ctx context.Context) (WiFi, error)
	}
	// LastMileCollector traces the path to a key target.
	LastMileCollector interface {
		Collect(ctx context.Context, target string) (LastMile, error)
	}
	// SessionCollector measures a browser-session timing breakdown to a target.
	SessionCollector interface {
		Collect(ctx context.Context, target string) (Session, error)
	}
)

// Collector gathers one Sample from the injected sub-collectors, derives the
// gateway + per-segment metrics, computes the attribution, and applies the
// privacy policy — in that order, so attribution sees the full (pre-redaction)
// path while only redacted data ever leaves Collect.
type Collector struct {
	wifi     WiFiCollector
	lastmile LastMileCollector
	session  SessionCollector

	privacy    Privacy
	thresholds Thresholds
	target     string   // the key target for the last-mile trace
	sessions   []string // targets for browser-session timing
	tenant     string
	agent      string
	clock      func() time.Time
}

// NewCollector wires a collector. clock may be nil (defaults to time.Now).
func NewCollector(cfg *Config, wifi WiFiCollector, lm LastMileCollector, sess SessionCollector) *Collector {
	target := ""
	if len(cfg.Targets) > 0 {
		target = cfg.Targets[0]
	}
	return &Collector{
		wifi: wifi, lastmile: lm, session: sess,
		privacy: cfg.Privacy, thresholds: cfg.Thresholds,
		target: target, sessions: cfg.Targets,
		tenant: cfg.TenantID, agent: cfg.AgentID,
		clock: time.Now,
	}
}

// Collect gathers one Sample. Every sub-collector is best-effort: a failure
// degrades that signal to "unavailable" and the rest of the sample still forms.
func (c *Collector) Collect(ctx context.Context) Sample {
	now := time.Now
	if c.clock != nil {
		now = c.clock
	}
	s := Sample{TenantID: c.tenant, AgentID: c.agent, Timestamp: now()}

	if c.wifi != nil {
		if w, err := c.wifi.Collect(ctx); err == nil {
			s.WiFi = w
		} else {
			s.Unavailable = append(s.Unavailable, "wifi: "+err.Error())
		}
	}
	if c.lastmile != nil && c.target != "" {
		// DPR-061: targets are URLs ("https://1.1.1.1"); traceroute wants the
		// host. The URL used to be handed over verbatim, so the last-mile trace
		// never ran with the documented configuration.
		if lm, err := c.lastmile.Collect(ctx, traceHost(c.target)); err == nil {
			lm.Target = c.target
			lm.classify()
			s.LastMile = lm
			if lm.ISPRTTMs == 0 && lm.ISPLossPct == 0 {
				s.Unavailable = append(s.Unavailable, fmt.Sprintf("isp_edge: no public hop answered within %d hops (reached=%t)", len(lm.Hops), lm.Reached))
			}
		} else {
			s.Unavailable = append(s.Unavailable, "last_mile: "+err.Error())
		}
	}
	s.Gateway = gatewayFromLastMile(s.LastMile)
	if c.session != nil {
		for _, t := range c.sessions {
			if sess, err := c.session.Collect(ctx, t); err == nil {
				s.Sessions = append(s.Sessions, sess)
			}
		}
	}

	s.Attribution = Attribute(s, c.thresholds)
	c.privacy.Apply(&s) // redact identifiers AFTER attribution has seen the full path
	return s
}

// traceHost reduces a session target to what a path trace needs: the host of
// a URL (scheme, port and path stripped; IPv6 brackets removed), the host of a
// host:port pair, or the value itself.
func traceHost(target string) string {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil && h != "" {
		return h
	}
	return strings.Trim(t, "[]")
}

// HTTPSessionCollector measures a browser-session timing breakdown with httptrace
// over the hardened (certificate-validating) transport. It is portable and
// fully testable (no browser, no privilege), and is the default SessionCollector.
type HTTPSessionCollector struct {
	client *http.Client
}

// NewHTTPSessionCollector builds a session collector. timeout <= 0 uses a default.
func NewHTTPSessionCollector(timeout time.Duration) *HTTPSessionCollector {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPSessionCollector{client: crypto.HardenedHTTPClient(timeout)}
}

// Collect performs one GET and records the DNS/connect/TLS/TTFB/total split.
func (h *HTTPSessionCollector) Collect(ctx context.Context, target string) (Session, error) {
	out := Session{Target: target}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		out.Error = err.Error()
		return out, nil // a bad target is a failed session, not a collector fault
	}
	req.Header.Set("User-Agent", "probectl-endpoint-dem")

	var dnsStart, connStart, tlsStart, reqStart time.Time
	reqStart = time.Now()
	// TLS measured TLSHandshakeStart→GotConn (importing crypto/tls outside
	// internal/crypto trips the FIPS guard), the same approach as the browser
	// HTTP driver.
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { out.DNSms = sinceMs(dnsStart) },
		ConnectStart:      func(string, string) { connStart = time.Now() },
		ConnectDone:       func(string, string, error) { out.ConnectMs = sinceMs(connStart) },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		GotConn: func(httptrace.GotConnInfo) {
			if !tlsStart.IsZero() {
				out.TLSms = sinceMs(tlsStart)
			}
		},
		GotFirstResponseByte: func() { out.TTFBms = float64(time.Since(reqStart).Milliseconds()) },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// DPR-063: every sample must dial afresh, or DNS/connect/TLS read 0 on a
	// kept-alive connection and only TTFB/total are measured per interval.
	defer h.client.CloseIdleConnections()
	resp, err := h.client.Do(req)
	if err != nil {
		out.Error = err.Error()
		out.TotalMs = float64(time.Since(reqStart).Milliseconds())
		return out, nil
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	out.TotalMs = float64(time.Since(reqStart).Milliseconds())
	out.Status = resp.StatusCode
	out.Success = resp.StatusCode < 500
	return out, nil
}

func sinceMs(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(time.Since(t).Milliseconds())
}
