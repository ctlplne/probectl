// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package canary_test

import (
	"context"
	"crypto"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/imfeelingtheagi/probectl/internal/canary"
)

// serveDNS starts in-process UDP and TCP DNS servers sharing one handler and
// returns their addresses — a hermetic resolver, no public network needed.
func serveDNS(t *testing.T, h dns.Handler) (udpAddr, tcpAddr string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	su := &dns.Server{PacketConn: pc, Handler: h}
	st := &dns.Server{Listener: l, Handler: h}
	go func() { _ = su.ActivateAndServe() }()
	go func() { _ = st.ActivateAndServe() }()
	t.Cleanup(func() { _ = su.Shutdown(); _ = st.Shutdown() })
	return pc.LocalAddr().String(), l.Addr().String()
}

func aRecord(name, ip string) *dns.A {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}
}

func TestDNSResolverUDPAndTCP(t *testing.T) {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = []dns.RR{aRecord(r.Question[0].Name, "203.0.113.10")}
		_ = w.WriteMsg(m)
	})
	udp, tcp := serveDNS(t, h)

	for _, tc := range []struct{ transport, server string }{
		{"udp", udp},
		{"tcp", tcp},
	} {
		t.Run(tc.transport, func(t *testing.T) {
			c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "example.com", Timeout: 2 * time.Second,
				Params: map[string]string{"allow_private_targets": "true", "transport": tc.transport, "server": tc.server}})
			if err != nil {
				t.Fatal(err)
			}
			res, err := c.Run(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !res.Success {
				t.Fatalf("success=false err=%q", res.Error)
			}
			if res.Metrics["dns.answers"] != 1 {
				t.Errorf("dns.answers = %v, want 1", res.Metrics["dns.answers"])
			}
			if _, ok := res.Metrics["dns.query.ms"]; !ok {
				t.Error("missing dns.query.ms")
			}
			if res.Attributes["probectl.dns.rcode"] != "NOERROR" {
				t.Errorf("rcode = %q", res.Attributes["probectl.dns.rcode"])
			}
			if res.Attributes["probectl.dns.answer"] != "A 203.0.113.10" {
				t.Errorf("answer = %q", res.Attributes["probectl.dns.answer"])
			}
		})
	}
}

func TestDNSResolverNXDOMAIN(t *testing.T) {
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Authoritative = true
		_ = w.WriteMsg(m)
	})
	udp, _ := serveDNS(t, h)

	c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "nope.example", Timeout: 2 * time.Second,
		Params: map[string]string{"allow_private_targets": "true", "server": udp}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Success {
		t.Error("NXDOMAIN should be success=false")
	}
	if res.Attributes["probectl.dns.rcode"] != "NXDOMAIN" {
		t.Errorf("rcode = %q, want NXDOMAIN", res.Attributes["probectl.dns.rcode"])
	}
}

func TestDNSOverHTTPS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		req := new(dns.Msg)
		if err := req.Unpack(body); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = []dns.RR{aRecord(req.Question[0].Name, "198.51.100.7")}
		wire, _ := m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer srv.Close()

	c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "example.org", Timeout: 2 * time.Second,
		Params: map[string]string{"allow_private_targets": "true", "transport": "doh", "server": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || res.Attributes["probectl.dns.answer"] != "A 198.51.100.7" {
		t.Fatalf("doh: success=%v answer=%q err=%q", res.Success, res.Attributes["probectl.dns.answer"], res.Error)
	}
}

// signForZone builds a signed A RRset and the matching DNSKEY for in-process
// DNSSEC tests. expired=true puts the signature outside its validity window.
func signForZone(t *testing.T, name, ip string, expired bool) (a *dns.A, sig *dns.RRSIG, key *dns.DNSKEY) {
	t.Helper()
	key = &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer := priv.(crypto.Signer)
	a = aRecord(name, ip)
	a.Hdr.Ttl = 3600
	incep := time.Now().Add(-time.Hour)
	expir := time.Now().Add(time.Hour)
	if expired {
		incep = time.Now().Add(-2 * time.Hour)
		expir = time.Now().Add(-time.Hour)
	}
	sig = &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ECDSAP256SHA256,
		Inception:  uint32(incep.Unix()),
		Expiration: uint32(expir.Unix()),
		KeyTag:     key.KeyTag(),
		SignerName: name,
	}
	if err := sig.Sign(signer, []dns.RR{a}); err != nil {
		t.Fatal(err)
	}
	return a, sig, key
}

// dnssecHandler answers A with the signed RRset (no key inline → forces a DNSKEY
// fetch) and answers DNSKEY with the zone key.
func dnssecHandler(a *dns.A, sig *dns.RRSIG, key *dns.DNSKEY) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		switch r.Question[0].Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{a, sig}
		case dns.TypeDNSKEY:
			m.Answer = []dns.RR{key}
		}
		_ = w.WriteMsg(m)
	}
}

func TestDNSSECSecure(t *testing.T) {
	a, sig, key := signForZone(t, "example.com.", "203.0.113.55", false)
	udp, _ := serveDNS(t, dnssecHandler(a, sig, key))

	c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "example.com", Timeout: 2 * time.Second,
		Params: map[string]string{"allow_private_targets": "true", "server": udp, "dnssec": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("success=false err=%q", res.Error)
	}
	if res.Attributes["probectl.dns.dnssec"] != "secure" {
		t.Errorf("probectl.dns.dnssec = %q, want secure", res.Attributes["probectl.dns.dnssec"])
	}
	if res.Metrics["dns.dnssec.secure"] != 1 {
		t.Errorf("dns.dnssec.secure = %v, want 1", res.Metrics["dns.dnssec.secure"])
	}
}

func TestDNSSECBogus(t *testing.T) {
	// An expired signature must be reported bogus — NOT silently trusted.
	a, sig, key := signForZone(t, "example.com.", "203.0.113.55", true)
	udp, _ := serveDNS(t, dnssecHandler(a, sig, key))

	c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "example.com", Timeout: 2 * time.Second,
		Params: map[string]string{"allow_private_targets": "true", "server": udp, "dnssec": "true"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Success {
		t.Error("bogus DNSSEC must fail the probe")
	}
	if res.Attributes["probectl.dns.dnssec"] != "bogus" {
		t.Errorf("probectl.dns.dnssec = %q, want bogus", res.Attributes["probectl.dns.dnssec"])
	}
}

// TestDNSLiveDoT and TestDNSLiveTrace exercise the real network paths
// (DoT to a public resolver; an iterative delegation walk from the roots). They
// skip cleanly where outbound DNS is unavailable.
func TestDNSLiveDoT(t *testing.T) {
	c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "example.com", Timeout: 4 * time.Second,
		Params: map[string]string{"transport": "dot", "server": "1.1.1.1:853"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Skipf("DoT unavailable in this environment: %v", res.Error)
	}
	if res.Attributes["probectl.dns.transport"] != "dot" {
		t.Errorf("transport attr = %q", res.Attributes["probectl.dns.transport"])
	}
}

func TestDNSLiveTrace(t *testing.T) {
	c, err := canary.NewDNS(canary.Config{Type: "dns", Target: "www.iana.org", Timeout: 4 * time.Second,
		Params: map[string]string{"mode": "trace"}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Skipf("trace unavailable in this environment: %v", res.Error)
	}
	if res.Metrics["dns.trace.hops"] < 2 {
		t.Errorf("trace hops = %v, want a multi-step delegation", res.Metrics["dns.trace.hops"])
	}
	if res.Attributes["probectl.dns.trace"] == "" {
		t.Error("missing dns.trace chain")
	}
}
