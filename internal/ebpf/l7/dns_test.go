package l7

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSQueryResponse(t *testing.T) {
	p := newDNSParser()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Id = 0x1234
	qb, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	r := new(dns.Msg)
	r.SetReply(q)
	r.Rcode = dns.RcodeNameError // NXDOMAIN
	rb, err := r.Pack()
	if err != nil {
		t.Fatal(err)
	}

	t0 := time.Unix(5, 0)
	if c := p.OnData(DataEvent{Kind: Request, Time: t0, Payload: qb}); len(c) != 0 {
		t.Fatalf("query emitted %d calls, want 0", len(c))
	}
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(3 * time.Millisecond), Payload: rb})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoDNS || c.Method != "A" || c.Resource != "example.com." || c.Status != "NXDOMAIN" || !c.Error {
		t.Errorf("call = %+v", c)
	}
	if c.Latency != 3*time.Millisecond {
		t.Errorf("latency = %v", c.Latency)
	}
}

// FUZZ-001: flooding unanswered queries keeps the pending map bounded, and a
// legitimate query→response still matches afterward.
func TestDNSPendingMapBounded(t *testing.T) {
	p := newDNSParser()
	base := time.Unix(1000, 0)
	for i := 0; i < dnsMaxPending+2000; i++ {
		q := new(dns.Msg)
		q.SetQuestion("flood.example.", dns.TypeA)
		q.Id = uint16(i)
		qb, _ := q.Pack()
		// Recent (monotonic) timestamps so the TTL sweep can't clear them —
		// forces the oldest-eviction backstop to hold the cap.
		p.OnData(DataEvent{Kind: Request, Time: base.Add(time.Duration(i) * time.Millisecond), Payload: qb})
	}
	if n := len(p.pending); n > dnsMaxPending {
		t.Fatalf("pending map unbounded: %d entries (cap %d)", n, dnsMaxPending)
	}

	// A normal query→response still matches within the window after the flood.
	now := base.Add(time.Hour)
	q := new(dns.Msg)
	q.SetQuestion("ok.example.", dns.TypeAAAA)
	q.Id = 0xBEEF
	qb, _ := q.Pack()
	p.OnData(DataEvent{Kind: Request, Time: now, Payload: qb})
	r := new(dns.Msg)
	r.SetReply(q)
	rb, _ := r.Pack()
	calls := p.OnData(DataEvent{Kind: Response, Time: now.Add(2 * time.Millisecond), Payload: rb})
	if len(calls) != 1 || calls[0].Resource != "ok.example." || calls[0].Method != "AAAA" {
		t.Fatalf("legitimate match broke after flood: %+v", calls)
	}
}

// FUZZ-001: an abandoned (TTL-expired) query is swept under cap pressure, so a
// very late response no longer mis-correlates — stale entries don't accumulate.
func TestDNSPendingTTLEviction(t *testing.T) {
	p := newDNSParser()
	old := new(dns.Msg)
	old.SetQuestion("old.example.", dns.TypeA)
	old.Id = 1
	ob, _ := old.Pack()
	t0 := time.Unix(2000, 0)
	p.OnData(DataEvent{Kind: Request, Time: t0, Payload: ob})

	// Fill to the cap with queries a minute later → the next insert triggers
	// evictExpired, which drops the old one (age > dnsPendingTTL).
	future := t0.Add(time.Minute)
	for i := 2; i < dnsMaxPending+2; i++ {
		q := new(dns.Msg)
		q.SetQuestion("x.example.", dns.TypeA)
		q.Id = uint16(i)
		qb, _ := q.Pack()
		p.OnData(DataEvent{Kind: Request, Time: future, Payload: qb})
	}

	resp := new(dns.Msg)
	resp.SetReply(old)
	rb, _ := resp.Pack()
	if calls := p.OnData(DataEvent{Kind: Response, Time: future, Payload: rb}); len(calls) != 0 {
		t.Fatalf("TTL-expired query must not match a late response: %+v", calls)
	}
}
