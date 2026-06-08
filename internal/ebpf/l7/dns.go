package l7

import (
	"time"

	"github.com/miekg/dns"
)

// FUZZ-001: the pending-query map is BOUNDED. An unmatched query (a response
// that never arrives — a lossy network, or an attacker flooding queries) would
// otherwise pin a dnsReq until its 16-bit id is reused; over many ids that is
// up to 65 536 stale entries per parser, and stale entries also risk
// mis-correlating a late/spoofed response. So a query older than the TTL is
// abandoned (no legitimate response will follow), and a hard cap evicts the
// oldest in-flight query under a flood — the map can never exceed dnsMaxPending.
const (
	dnsMaxPending = 4096             // hard cap on in-flight unmatched queries
	dnsPendingTTL = 10 * time.Second // a query older than this is abandoned
)

// dnsParser parses DNS (UDP payloads, or TCP with a 2-byte length prefix). It
// matches a response to its query by the DNS message id and reports the qtype as
// the method, the qname as the resource, and the rcode as the status.
type dnsParser struct {
	pending map[uint16]dnsReq
}

type dnsReq struct {
	qname string
	qtype string
	start time.Time
	bytes uint64
}

func newDNSParser() *dnsParser { return &dnsParser{pending: map[uint16]dnsReq{}} }

func (p *dnsParser) OnData(d DataEvent) []Call {
	msg, ok := unpackDNS(d.Payload)
	if !ok {
		return nil
	}
	// Use the QR bit, not the capture direction, to classify (robust for UDP).
	if !msg.Response {
		if len(msg.Question) > 0 {
			q := msg.Question[0]
			p.addPending(msg.Id, dnsReq{
				qname: q.Name,
				qtype: dns.TypeToString[q.Qtype],
				start: d.Time,
				bytes: uint64(len(d.Payload)),
			}, d.Time)
		}
		return nil
	}

	req, ok := p.pending[msg.Id]
	if !ok {
		return nil
	}
	delete(p.pending, msg.Id)
	return []Call{{
		Protocol:  ProtoDNS,
		Method:    req.qtype,
		Resource:  req.qname,
		Status:    dns.RcodeToString[msg.Rcode],
		Error:     msg.Rcode != dns.RcodeSuccess,
		Start:     req.start,
		Latency:   d.Time.Sub(req.start),
		ReqBytes:  req.bytes,
		RespBytes: uint64(len(d.Payload)),
	}}
}

func (p *dnsParser) Flush() []Call { return nil }

// addPending records an in-flight query, keeping the map bounded (FUZZ-001).
// Under pressure it first abandons TTL-expired queries (a timed-out query gets
// no matching response), then — if still at the cap (a flood of recent
// unanswered queries) — evicts the oldest, so len(pending) never exceeds
// dnsMaxPending. A normal query→response within the TTL still matches.
func (p *dnsParser) addPending(id uint16, req dnsReq, now time.Time) {
	if len(p.pending) >= dnsMaxPending {
		p.evictExpired(now)
	}
	if len(p.pending) >= dnsMaxPending {
		p.evictOldest()
	}
	p.pending[id] = req
}

// evictExpired drops queries older than the TTL (abandoned — no response will
// come).
func (p *dnsParser) evictExpired(now time.Time) {
	for id, r := range p.pending {
		if now.Sub(r.start) > dnsPendingTTL {
			delete(p.pending, id)
		}
	}
}

// evictOldest drops the single oldest in-flight query (flood backstop).
func (p *dnsParser) evictOldest() {
	var oldestID uint16
	var oldest time.Time
	first := true
	for id, r := range p.pending {
		if first || r.start.Before(oldest) {
			oldestID, oldest, first = id, r.start, false
		}
	}
	if !first {
		delete(p.pending, oldestID)
	}
}

func unpackDNS(b []byte) (*dns.Msg, bool) {
	try := func(data []byte) (*dns.Msg, bool) {
		m := new(dns.Msg)
		if err := m.Unpack(data); err != nil {
			return nil, false
		}
		return m, true
	}
	if m, ok := try(b); ok {
		return m, true
	}
	if len(b) > 2 { // TCP framing: 2-byte length prefix
		if m, ok := try(b[2:]); ok {
			return m, true
		}
	}
	return nil, false
}
