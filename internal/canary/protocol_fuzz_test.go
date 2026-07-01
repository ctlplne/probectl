// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"bytes"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// FuzzDNSDoHResponseSummary covers the DNS-over-HTTPS response boundary:
// production reads at most 64 KiB, unpacks DNS wire bytes, then summarizes the
// answer section for the probe result. Corrupt responses must simply fail
// decode; valid but odd RRsets must not panic the summary helpers.
func FuzzDNSDoHResponseSummary(f *testing.F) {
	f.Add(packedAResponse())
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<16 {
			body = body[:1<<16]
		}
		msg := new(dns.Msg)
		if err := msg.Unpack(body); err != nil {
			return
		}
		if got := countAnswers(msg); got < 0 || got > len(msg.Answer) {
			t.Fatalf("countAnswers = %d, answers = %d", got, len(msg.Answer))
		}
		_ = summarizeAnswers(msg)
	})
}

// FuzzHTTPExpectAndDrain keeps the HTTP canary's two raw config/response
// parsers under fuzz coverage: expect_status grammar and capped response body
// draining. The drain invariant is intentionally tiny: never report more bytes
// than the input or the configured cap.
func FuzzHTTPExpectAndDrain(f *testing.F) {
	f.Add("2xx,404,500-503", []byte("hello"), int64(5))
	f.Add("600", []byte{}, int64(0))
	f.Add(" 200 - 204 ,, 3xx ", []byte("abcdef"), int64(3))

	f.Fuzz(func(t *testing.T, expect string, body []byte, limit int64) {
		if len(expect) > 4096 {
			expect = expect[:4096]
		}
		if len(body) > 1<<20 {
			body = body[:1<<20]
		}
		if limit > 1<<20 {
			limit = 1 << 20
		}
		if limit < -1<<20 {
			limit = -1 << 20
		}

		ranges, err := parseExpectStatus(expect)
		if err == nil {
			for _, r := range ranges {
				if r.lo < 100 || r.hi > 599 || r.lo > r.hi {
					t.Fatalf("invalid parsed range from %q: %+v", expect, r)
				}
			}
			_ = describeExpect(ranges)
		}

		n := drainHTTPBody(bytes.NewReader(body), limit)
		effectiveLimit := limit
		if effectiveLimit < 0 {
			effectiveLimit = 0
		}
		if n < 0 || n > int64(len(body)) || n > effectiveLimit {
			t.Fatalf("drainHTTPBody read %d bytes, len=%d limit=%d", n, len(body), limit)
		}
	})
}

func packedAResponse() []byte {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Response = true
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		A: net.IPv4(192, 0, 2, 1),
	})
	wire, _ := msg.Pack()
	return wire
}
