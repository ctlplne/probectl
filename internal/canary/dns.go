// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const dnsType = "dns"

// dnsCanary queries DNS (resolver or delegation-trace mode) over UDP/TCP/DoT/DoH,
// optionally validating DNSSEC. The crypto lives entirely in miekg/dns (FIPS
// enabler intact — CLAUDE.md §7 guardrail 3).
type dnsCanary struct {
	guard     *TargetGuard
	name      string
	server    string
	qtype     uint16
	transport string // udp | tcp | dot | doh
	mode      string // resolver | trace
	dnssec    bool
	timeout   time.Duration
}

// NewDNS builds a DNS canary. Target is the query name. Params: server (resolver
// host[:port] or DoH URL), type (A, AAAA, MX, TXT, NS, ...), transport
// (udp|tcp|dot|doh), mode (resolver|trace), dnssec (true|false).
func NewDNS(cfg Config) (Canary, error) {
	name := strings.TrimSpace(cfg.Target)
	if name == "" {
		return nil, errors.New("dns: target (the query name) is required")
	}
	c := &dnsCanary{name: dns.Fqdn(name), qtype: dns.TypeA, transport: "udp", mode: "resolver", timeout: cfg.Timeout}
	if c.timeout <= 0 {
		c.timeout = 5 * time.Second
	}
	p := cfg.Params
	c.server = p["server"]
	c.guard = GuardFromParams(cfg.Params)
	// SSRF guard (U-002): an EXPLICIT resolver target is validated (and
	// enforced again at dial time). The system default from /etc/resolv.conf
	// is exempt — it is the host's own resolver, not request-supplied.
	if c.server != "" {
		host := c.server
		if h, _, err := net.SplitHostPort(c.server); err == nil {
			host = h
		}
		if err := c.guard.CheckHost(host); err != nil {
			return nil, fmt.Errorf("dns: %w", err)
		}
	}
	if v := p["type"]; v != "" {
		t, ok := dns.StringToType[strings.ToUpper(v)]
		if !ok {
			return nil, fmt.Errorf("dns: unknown record type %q", v)
		}
		c.qtype = t
	}
	switch p["transport"] {
	case "", "udp":
		c.transport = "udp"
	case "tcp", "dot", "doh":
		c.transport = p["transport"]
	default:
		return nil, fmt.Errorf("dns: unknown transport %q (want udp|tcp|dot|doh)", p["transport"])
	}
	switch p["mode"] {
	case "", "resolver":
		c.mode = "resolver"
	case "trace":
		c.mode = "trace"
	default:
		return nil, fmt.Errorf("dns: unknown mode %q (want resolver|trace)", p["mode"])
	}
	c.dnssec = p["dnssec"] == "true"
	if c.server == "" {
		c.server = defaultServer(c.transport)
	}
	return c, nil
}

// Describe returns the DNS canary spec.
func (c *dnsCanary) Describe() Spec {
	return Spec{Type: dnsType, Version: "1", Description: "DNS resolver/trace query with DNSSEC validation"}
}

// Run performs one DNS measurement.
func (c *dnsCanary) Run(ctx context.Context) (Result, error) {
	start := time.Now()
	res := Result{Type: dnsType, Target: strings.TrimSuffix(c.name, "."), StartedAt: start, Attributes: map[string]string{
		"probectl.dns.qtype":     dns.TypeToString[c.qtype],
		"probectl.dns.transport": c.transport,
		"probectl.dns.mode":      c.mode,
		"probectl.dns.server":    c.server,
	}}
	if c.mode == "trace" {
		return c.runTrace(ctx, res), nil
	}
	return c.runResolver(ctx, res), nil
}

func (c *dnsCanary) runResolver(ctx context.Context, res Result) Result {
	msg, rtt, err := c.query(ctx, c.server, c.name, c.qtype, c.dnssec)
	res.Duration = time.Since(res.StartedAt)
	if err != nil {
		res.Success = false
		res.Error = err.Error()
		res.Metrics = map[string]float64{}
		return res
	}
	res.Metrics = map[string]float64{
		"dns.query.ms": round(float64(rtt)/float64(time.Millisecond), 3),
		"dns.answers":  float64(countAnswers(msg)),
	}
	res.Attributes["probectl.dns.rcode"] = dns.RcodeToString[msg.Rcode]
	res.Attributes["probectl.dns.answer"] = summarizeAnswers(msg)

	if c.dnssec {
		status := validateDNSSEC(ctx, c, msg)
		res.Attributes["probectl.dns.dnssec"] = status
		res.Metrics["dns.dnssec.secure"] = boolFloat(status == dnssecSecure)
		if status == dnssecBogus {
			res.Success = false
			res.Error = "DNSSEC validation failed (bogus)"
			return res
		}
	} else {
		res.Attributes["probectl.dns.dnssec"] = "disabled"
	}

	res.Success = msg.Rcode == dns.RcodeSuccess && countAnswers(msg) > 0
	if !res.Success && res.Error == "" {
		res.Error = fmt.Sprintf("dns rcode %s with %d answers", dns.RcodeToString[msg.Rcode], countAnswers(msg))
	}
	return res
}

// query sends one DNS query over the configured transport and returns the
// response and the round-trip time.
func (c *dnsCanary) query(ctx context.Context, server, name string, qtype uint16, dnssec bool) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.RecursionDesired = c.mode == "resolver"
	if dnssec {
		m.SetEdns0(4096, true) // request DNSSEC records (DO bit)
	}
	if c.transport == "doh" {
		return c.queryDoH(ctx, server, m)
	}
	client := &dns.Client{Timeout: c.timeout}
	if c.server != "" { // explicit resolver: enforce the guard at dial time too
		client.Dialer = &net.Dialer{Timeout: c.timeout, Control: c.guard.DialControl(nil)}
	}
	addr := withDefaultPort(server, "53")
	switch c.transport {
	case "tcp":
		client.Net = "tcp"
	case "dot":
		client.Net = "tcp-tls"
		client.TLSConfig = &tls.Config{ServerName: hostOnly(server), MinVersion: tls.VersionTLS12}
		addr = withDefaultPort(server, "853")
	}
	return client.ExchangeContext(ctx, m, addr)
}

func (c *dnsCanary) queryDoH(ctx context.Context, endpoint string, m *dns.Msg) (*dns.Msg, time.Duration, error) {
	wire, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	start := time.Now()
	dohClient := &http.Client{Timeout: c.timeout}
	if c.server != "" {
		dohClient.Transport = &http.Transport{DialContext: (&net.Dialer{
			Timeout: c.timeout,
			Control: c.guard.DialControl(nil),
		}).DialContext}
	}
	resp, err := dohClient.Do(req)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, fmt.Errorf("doh request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return nil, rtt, fmt.Errorf("doh status %d", resp.StatusCode)
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, rtt, fmt.Errorf("doh decode: %w", err)
	}
	return r, rtt, nil
}

// --- helpers ---

func countAnswers(m *dns.Msg) int {
	n := 0
	for _, rr := range m.Answer {
		if _, ok := rr.(*dns.RRSIG); !ok {
			n++
		}
	}
	return n
}

// summarizeAnswers renders a compact, stable summary of the answer rdata.
func summarizeAnswers(m *dns.Msg) string {
	var parts []string
	for _, rr := range m.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			continue
		}
		f := strings.Fields(rr.String()) // name ttl class type rdata...
		if len(f) >= 5 {
			parts = append(parts, dns.TypeToString[rr.Header().Rrtype]+" "+strings.Join(f[4:], " "))
		}
	}
	sort.Strings(parts)
	if len(parts) > 8 {
		parts = append(parts[:8], "…")
	}
	return strings.Join(parts, ", ")
}

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func withDefaultPort(server, port string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, port)
}

func hostOnly(server string) string {
	if h, _, err := net.SplitHostPort(server); err == nil {
		return h
	}
	return server
}

func defaultServer(transport string) string {
	switch transport {
	case "doh":
		return "https://cloudflare-dns.com/dns-query"
	case "dot":
		return "1.1.1.1:853"
	default:
		if cc, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && len(cc.Servers) > 0 {
			return net.JoinHostPort(cc.Servers[0], cc.Port)
		}
		return "1.1.1.1:53"
	}
}
