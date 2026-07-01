// SPDX-License-Identifier: LicenseRef-probectl-TBD

package threat

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
)

// CTChecker correlates a leaf certificate against Certificate Transparency logs
// for issuance anomalies. Implementations MUST fetch over TLS (cert-validated),
// respect the source's AUP / rate limits, and DEGRADE GRACEFULLY — a down or
// rate-limited CT source returns ok=false, never an error that breaks posture
// (CLAUDE.md §7 guardrail 10).
type CTChecker interface {
	Check(ctx context.Context, leaf *x509.Certificate) (Finding, bool)
}

// CrtSh queries crt.sh's JSON API for a certificate's serial. It is OFF by default
// (external fetch — sovereignty / no-phone-home, and crt.sh AUP / rate limits);
// operators opt in. A serial unknown to CT surfaces a low-severity
// ct_not_logged anomaly; any error or a logged cert yields no finding.
type CrtSh struct {
	endpoint string
	client   *http.Client

	mu          sync.Mutex
	cache       map[string]ctCacheEntry
	cacheOrder  []string
	cacheMax    int
	hosts       map[string]*ctHostState
	minInterval time.Duration
	baseBackoff time.Duration
	maxBackoff  time.Duration
	now         func() time.Time
	stats       CrtShStats
	metrics     crtShMetrics
}

const (
	defaultCrtShCacheMax    = 1024
	defaultCrtShMinInterval = 200 * time.Millisecond
	defaultCrtShBaseBackoff = time.Second
	defaultCrtShMaxBackoff  = time.Minute
)

type ctCacheEntry struct {
	finding Finding
	ok      bool
}

type ctHostState struct {
	nextAllowed  time.Time
	backoffUntil time.Time
	failures     int
}

// CrtShStats is process-local CT checker health. It carries no tenant data.
type CrtShStats struct {
	CacheHits          uint64
	CacheMisses        uint64
	Requests           uint64
	SkippedRateLimited uint64
	SkippedBackoff     uint64
	Degraded           uint64
}

type crtShMetrics struct {
	cacheHits, cacheMisses, requests   *metrics.Counter
	skippedRateLimited, skippedBackoff *metrics.Counter
	degraded                           *metrics.Counter
}

// NewCrtSh builds a crt.sh checker. endpoint defaults to https://crt.sh.
func NewCrtSh(endpoint string, timeout time.Duration) *CrtSh {
	if endpoint == "" {
		endpoint = "https://crt.sh"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if !ctEndpointTransportAllowed(endpoint) {
		endpoint = ""
	}
	return &CrtSh{
		endpoint:    endpoint,
		client:      crypto.HardenedHTTPClient(timeout),
		cacheMax:    defaultCrtShCacheMax,
		minInterval: defaultCrtShMinInterval,
		baseBackoff: defaultCrtShBaseBackoff,
		maxBackoff:  defaultCrtShMaxBackoff,
		now:         time.Now,
	}
}

// WithMetrics exposes aggregate CT checker health at /metrics. These counters
// are process-wide and contain no tenant, certificate, serial, or domain labels.
func (c *CrtSh) WithMetrics(reg *metrics.Registry) *CrtSh {
	if c == nil || reg == nil {
		return c
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.metrics = crtShMetrics{
		cacheHits:          reg.Counter("probectl_ct_cache_hits_total", "Certificate Transparency checker cache hits."),
		cacheMisses:        reg.Counter("probectl_ct_cache_misses_total", "Certificate Transparency checker cache misses."),
		requests:           reg.Counter("probectl_ct_requests_total", "Certificate Transparency HTTP lookups attempted."),
		skippedRateLimited: reg.Counter("probectl_ct_skipped_rate_limited_total", "Certificate Transparency lookups skipped by the per-host rate limiter."),
		skippedBackoff:     reg.Counter("probectl_ct_skipped_backoff_total", "Certificate Transparency lookups skipped while a host circuit breaker was open."),
		degraded:           reg.Counter("probectl_ct_degraded_total", "Certificate Transparency lookups that degraded because the upstream errored, throttled, or returned malformed JSON."),
	}
	return c
}

// Stats returns a snapshot of CT checker health for tests and diagnostics.
func (c *CrtSh) Stats() CrtShStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Check queries crt.sh by the cert's serial number.
func (c *CrtSh) Check(ctx context.Context, leaf *x509.Certificate) (Finding, bool) {
	if c.endpoint == "" || leaf == nil || leaf.SerialNumber == nil {
		return Finding{}, false
	}
	serial := fmt.Sprintf("%x", leaf.SerialNumber)
	cacheKey := c.cacheKey(serial, leaf)
	if ent, ok := c.getCached(cacheKey); ok {
		return ent.finding, ent.ok
	}

	host := c.endpointHost()
	if reason, ok := c.reserveHost(host); !ok {
		c.recordSkip(reason)
		return Finding{}, false
	}

	endpoint := c.endpoint + "/?serial=" + url.QueryEscape(serial) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		c.recordDegraded(host)
		return Finding{}, false
	}
	c.recordRequest()
	resp, err := c.client.Do(req)
	if err != nil {
		c.recordDegraded(host)
		return Finding{}, false // CT down / unreachable → graceful no-op
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		c.recordDegraded(host)
		return Finding{}, false // rate-limited / error → graceful no-op
	}
	var entries []map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&entries); err != nil {
		c.recordDegraded(host)
		return Finding{}, false
	}
	c.recordSuccess(host)
	if len(entries) == 0 {
		f := Finding{
			Kind:     FindingCTNotLogged,
			Severity: SeverityInfo,
			Message:  "certificate serial not found in Certificate Transparency logs",
		}
		c.putCache(cacheKey, ctCacheEntry{finding: f, ok: true})
		return f, true
	}
	c.putCache(cacheKey, ctCacheEntry{})
	return Finding{}, false // present in CT → no anomaly
}

func (c *CrtSh) cacheKey(serial string, leaf *x509.Certificate) string {
	fp := crypto.CertSHA1(leaf)
	if fp == "" {
		return strings.ToLower(serial)
	}
	return strings.ToLower(serial) + "/" + fp
}

func (c *CrtSh) getCached(key string) (ctCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureStateLocked()
	ent, ok := c.cache[key]
	if ok {
		c.stats.CacheHits++
		if c.metrics.cacheHits != nil {
			c.metrics.cacheHits.Inc()
		}
		return ent, true
	}
	c.stats.CacheMisses++
	if c.metrics.cacheMisses != nil {
		c.metrics.cacheMisses.Inc()
	}
	return ctCacheEntry{}, false
}

func (c *CrtSh) putCache(key string, ent ctCacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureStateLocked()
	if c.cacheMax <= 0 {
		return
	}
	if _, exists := c.cache[key]; !exists {
		for len(c.cache) >= c.cacheMax && len(c.cacheOrder) > 0 {
			old := c.cacheOrder[0]
			c.cacheOrder = c.cacheOrder[1:]
			delete(c.cache, old)
		}
		c.cacheOrder = append(c.cacheOrder, key)
	}
	c.cache[key] = ent
}

func (c *CrtSh) endpointHost() string {
	u, err := url.Parse(c.endpoint)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

func (c *CrtSh) reserveHost(host string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureStateLocked()
	now := c.now()
	st := c.hosts[host]
	if st == nil {
		st = &ctHostState{}
		c.hosts[host] = st
	}
	if now.Before(st.backoffUntil) {
		return "backoff", false
	}
	if now.Before(st.nextAllowed) {
		return "rate_limited", false
	}
	st.nextAllowed = now.Add(c.minInterval)
	return "", true
}

func (c *CrtSh) recordRequest() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.Requests++
	if c.metrics.requests != nil {
		c.metrics.requests.Inc()
	}
}

func (c *CrtSh) recordSkip(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch reason {
	case "backoff":
		c.stats.SkippedBackoff++
		if c.metrics.skippedBackoff != nil {
			c.metrics.skippedBackoff.Inc()
		}
	default:
		c.stats.SkippedRateLimited++
		if c.metrics.skippedRateLimited != nil {
			c.metrics.skippedRateLimited.Inc()
		}
	}
}

func (c *CrtSh) recordSuccess(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureStateLocked()
	st := c.hosts[host]
	if st == nil {
		return
	}
	st.failures = 0
	st.backoffUntil = time.Time{}
}

func (c *CrtSh) recordDegraded(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ensureStateLocked()
	c.stats.Degraded++
	if c.metrics.degraded != nil {
		c.metrics.degraded.Inc()
	}
	st := c.hosts[host]
	if st == nil {
		st = &ctHostState{}
		c.hosts[host] = st
	}
	st.failures++
	delay := c.baseBackoff
	for i := 1; i < st.failures && delay < c.maxBackoff; i++ {
		delay *= 2
	}
	if delay > c.maxBackoff {
		delay = c.maxBackoff
	}
	st.backoffUntil = c.now().Add(delay)
}

func (c *CrtSh) ensureStateLocked() {
	if c.cache == nil {
		c.cache = map[string]ctCacheEntry{}
	}
	if c.hosts == nil {
		c.hosts = map[string]*ctHostState{}
	}
	if c.cacheMax == 0 {
		c.cacheMax = defaultCrtShCacheMax
	}
	if c.minInterval == 0 {
		c.minInterval = defaultCrtShMinInterval
	}
	if c.baseBackoff == 0 {
		c.baseBackoff = defaultCrtShBaseBackoff
	}
	if c.maxBackoff == 0 {
		c.maxBackoff = defaultCrtShMaxBackoff
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.client == nil {
		c.client = crypto.HardenedHTTPClient(10 * time.Second)
	}
}

func ctEndpointTransportAllowed(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Hostname() == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
