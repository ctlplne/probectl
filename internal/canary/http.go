package canary

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const httpType = "http"

// defaultMaxBody caps the bytes read per probe so a huge response can't exhaust
// the agent; the body is read (not stored) only to time the full transfer.
const defaultMaxBody = 10 << 20 // 10 MiB

// httpCanary measures HTTP(S) availability with a full response-time breakdown
// (DNS / connect / TLS / TTFB / total) and throughput, and captures TLS handshake
// details (version, cipher, cert chain) into the result for the S27 TLS-posture
// plane. The crypto stays in crypto/tls + crypto/x509 (FIPS-swappable; CLAUDE.md
// §7 guardrail 3).
type httpCanary struct {
	url      string
	method   string
	scheme   string
	host     string
	port     string
	body     string
	expect   []statusRange
	follow   bool
	insecure bool
	caFile   string
	maxBody  int64
	timeout  time.Duration
}

// NewHTTP builds an HTTP canary. Target is the URL. Params: method (GET),
// expect_status ("2xx,3xx" | "200" | "200-204"), follow_redirects (true),
// insecure_skip_verify (false), ca_file (extra trust anchor), body,
// max_body_bytes.
func NewHTTP(cfg Config) (Canary, error) {
	raw := strings.TrimSpace(cfg.Target)
	if raw == "" {
		return nil, errors.New("http: target (the URL) is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("http: invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("http: url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("http: url %q has no host", raw)
	}

	c := &httpCanary{
		url:     u.String(),
		method:  http.MethodGet,
		scheme:  u.Scheme,
		host:    u.Hostname(),
		follow:  true,
		maxBody: defaultMaxBody,
		timeout: cfg.Timeout,
	}
	if c.timeout <= 0 {
		c.timeout = 10 * time.Second
	}
	if c.port = u.Port(); c.port == "" {
		if u.Scheme == "https" {
			c.port = "443"
		} else {
			c.port = "80"
		}
	}

	p := cfg.Params
	if v := strings.ToUpper(strings.TrimSpace(p["method"])); v != "" {
		c.method = v
	}
	c.body = p["body"]
	c.caFile = p["ca_file"]
	if p["follow_redirects"] == "false" {
		c.follow = false
	}
	if p["insecure_skip_verify"] == "true" {
		c.insecure = true
	}
	if v := strings.TrimSpace(p["max_body_bytes"]); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("http: invalid max_body_bytes %q", v)
		}
		c.maxBody = n
	}
	expect, err := parseExpectStatus(p["expect_status"])
	if err != nil {
		return nil, err
	}
	c.expect = expect
	return c, nil
}

// Describe returns the HTTP canary spec.
func (c *httpCanary) Describe() Spec {
	return Spec{Type: httpType, Version: "1", Description: "HTTP availability, timing breakdown, and TLS capture"}
}

// Run performs one HTTP request, timing each phase and capturing TLS details.
func (c *httpCanary) Run(ctx context.Context) (Result, error) {
	start := time.Now()
	res := Result{Type: httpType, Target: c.url, StartedAt: start, Metrics: map[string]float64{}, Attributes: map[string]string{
		"network.transport":     "tcp",
		"network.protocol.name": "http",
		"server.address":        c.host,
		"server.port":           c.port,
		"url.full":              c.url,
		"http.request.method":   c.method,
	}}

	roots, err := c.trustRoots()
	if err != nil {
		return res, err // configuration fault (bad ca_file) → internal error
	}

	var (
		tm       phaseTimer
		peerAddr string
		tlsState *tls.ConnectionState
	)
	trace := tm.clientTrace(start, &peerAddr)

	transport := &http.Transport{
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		Proxy:             http.ProxyFromEnvironment,
	}
	if c.scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: c.host,
			// We skip the runtime's own verification and verify manually in
			// VerifyConnection so the cert chain is captured even when it is
			// invalid (expired/untrusted) — S27 consumes the captured fields,
			// and an invalid cert still fails the probe below.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				snapshot := cs
				tlsState = &snapshot
				if c.insecure {
					return nil
				}
				return verifyPeer(cs, c.host, roots)
			},
		}
	}

	reqCtx, cancel := context.WithTimeout(httptrace.WithClientTrace(ctx, trace), c.timeout)
	defer cancel()

	var bodyReader io.Reader
	if c.body != "" {
		bodyReader = strings.NewReader(c.body)
	}
	req, err := http.NewRequestWithContext(reqCtx, c.method, c.url, bodyReader)
	if err != nil {
		return res, fmt.Errorf("http: build request: %w", err)
	}

	client := &http.Client{Transport: transport}
	if !c.follow {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	resp, err := client.Do(req)
	tm.attachTiming(&res)
	attachPeer(&res, peerAddr)
	attachTLS(&res, tlsState, start)

	if err != nil {
		// A network / TLS / timeout failure is a probe failure (availability),
		// not an internal plugin error — report it as success=false.
		res.Duration = time.Since(start)
		res.Success = false
		res.Error = err.Error()
		return res, nil
	}
	defer func() { _ = resp.Body.Close() }()

	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, c.maxBody))
	total := time.Since(start)

	res.Metrics["http.status"] = float64(resp.StatusCode)
	res.Metrics["http.total.ms"] = round(msf(total), 3)
	res.Metrics["http.content.bytes"] = float64(n)
	if total > 0 {
		res.Metrics["http.throughput.kbps"] = round(float64(n)*8/1000/total.Seconds(), 3)
	}
	res.Attributes["http.response.status_code"] = strconv.Itoa(resp.StatusCode)
	res.Attributes["network.protocol.version"] = resp.Proto

	res.Duration = time.Since(start)
	res.Success = c.statusOK(resp.StatusCode)
	if !res.Success {
		res.Error = fmt.Sprintf("unexpected HTTP status %d (want %s)", resp.StatusCode, describeExpect(c.expect))
	}
	return res, nil
}

func (c *httpCanary) statusOK(code int) bool {
	for _, r := range c.expect {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}

// trustRoots returns the verification root pool: the system pool plus any
// ca_file anchors, or nil to use the system pool alone.
func (c *httpCanary) trustRoots() (*x509.CertPool, error) {
	if c.caFile == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(c.caFile)
	if err != nil {
		return nil, fmt.Errorf("http: read ca_file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("http: ca_file %q has no usable certificates", c.caFile)
	}
	return pool, nil
}

// verifyPeer runs standard chain verification against roots (nil = system),
// checking the hostname — the same decision the runtime would make, but invoked
// after the chain has been captured.
func verifyPeer(cs tls.ConnectionState, host string, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("no peer certificates presented")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range cs.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
	})
	return err
}

// statusRange is an inclusive HTTP status-code range used by expect_status.
type statusRange struct{ lo, hi int }

// parseExpectStatus parses a comma list of exact codes (200), classes (2xx), and
// ranges (200-204). Empty defaults to 2xx + 3xx (available).
func parseExpectStatus(s string) ([]statusRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []statusRange{{200, 399}}, nil
	}
	var out []statusRange
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "":
			continue
		case len(tok) == 3 && strings.HasSuffix(tok, "xx"):
			d := tok[0]
			if d < '1' || d > '5' {
				return nil, fmt.Errorf("http: invalid status class %q", tok)
			}
			base := int(d-'0') * 100
			out = append(out, statusRange{base, base + 99})
		case strings.Contains(tok, "-"):
			lo, hi, ok := strings.Cut(tok, "-")
			l, e1 := strconv.Atoi(strings.TrimSpace(lo))
			h, e2 := strconv.Atoi(strings.TrimSpace(hi))
			if !ok || e1 != nil || e2 != nil || l < 100 || h > 599 || l > h {
				return nil, fmt.Errorf("http: invalid status range %q", tok)
			}
			out = append(out, statusRange{l, h})
		default:
			n, e := strconv.Atoi(tok)
			if e != nil || n < 100 || n > 599 {
				return nil, fmt.Errorf("http: invalid status code %q", tok)
			}
			out = append(out, statusRange{n, n})
		}
	}
	if len(out) == 0 {
		return nil, errors.New("http: expect_status has no valid entries")
	}
	return out, nil
}

func describeExpect(rs []statusRange) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		if r.lo == r.hi {
			parts = append(parts, strconv.Itoa(r.lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.lo, r.hi))
		}
	}
	return strings.Join(parts, ",")
}

// msf converts a duration to fractional milliseconds.
func msf(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func attachPeer(res *Result, peerAddr string) {
	if peerAddr == "" {
		return
	}
	if host, port, err := net.SplitHostPort(peerAddr); err == nil {
		res.Attributes["network.peer.address"] = host
		res.Attributes["network.peer.port"] = port
	} else {
		res.Attributes["network.peer.address"] = peerAddr
	}
}

func attachTLS(res *Result, cs *tls.ConnectionState, start time.Time) {
	if cs == nil {
		return
	}
	res.Attributes["tls.protocol.version"] = tlsVersionName(cs.Version)
	res.Attributes["tls.cipher"] = tls.CipherSuiteName(cs.CipherSuite)
	res.Attributes["tls.resumed"] = strconv.FormatBool(cs.DidResume)
	if len(cs.PeerCertificates) == 0 {
		return
	}
	leaf := cs.PeerCertificates[0]
	res.Attributes["tls.server.subject"] = leaf.Subject.String()
	res.Attributes["tls.server.issuer"] = leaf.Issuer.String()
	res.Attributes["tls.server.not_before"] = leaf.NotBefore.UTC().Format(time.RFC3339)
	res.Attributes["tls.server.not_after"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	if len(leaf.DNSNames) > 0 {
		res.Attributes["tls.server.san"] = strings.Join(leaf.DNSNames, ",")
	}
	res.Attributes["tls.server.chain"] = chainSummary(cs.PeerCertificates)
	res.Metrics["http.tls.cert_expiry_days"] = round(leaf.NotAfter.Sub(start).Hours()/24, 2)
}

// chainSummary renders the presented chain as "leafCN > issuerCN > rootCN" so
// S27 can reconstruct the chain shape from one captured field.
func chainSummary(chain []*x509.Certificate) string {
	parts := make([]string, 0, len(chain))
	for _, cert := range chain {
		cn := cert.Subject.CommonName
		if cn == "" {
			cn = cert.Subject.String()
		}
		parts = append(parts, cn)
	}
	return strings.Join(parts, " > ")
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
