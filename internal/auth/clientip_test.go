// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"net/http"
	"testing"
)

func TestClientIPHonorsForwardedHopsOnlyFromTrustedProxies(t *testing.T) {
	ingress, err := ParseTrustedProxies([]string{"10.244.0.0/16", " 192.0.2.10 ", "2001:db8::/48"})
	if err != nil {
		t.Fatal(err)
	}
	hdr := func(kv ...string) http.Header {
		h := http.Header{}
		for i := 0; i+1 < len(kv); i += 2 {
			h.Add(kv[i], kv[i+1])
		}
		return h
	}
	cases := []struct {
		name   string
		remote string
		header http.Header
		want   string
	}{
		{"no proxies configured: peer wins even with a header", "10.244.0.7:4000", hdr("X-Forwarded-For", "203.0.113.9"), "10.244.0.7"},
		{"trusted ingress forwards one client", "10.244.0.7:4000", hdr("X-Forwarded-For", "203.0.113.9"), "203.0.113.9"},
		{"client-supplied hop behind a trusted chain is ignored", "10.244.0.7:4000", hdr("X-Forwarded-For", "198.51.100.1, 203.0.113.9, 10.244.0.8"), "203.0.113.9"},
		{"untrusted peer spoofing the header keys on itself", "198.51.100.77:1", hdr("X-Forwarded-For", "203.0.113.9"), "198.51.100.77"},
		{"malformed hop stops the walk at the peer", "10.244.0.7:4000", hdr("X-Forwarded-For", "not-an-ip"), "10.244.0.7"},
		{"X-Real-IP fallback from a trusted proxy", "10.244.0.7:4000", hdr("X-Real-IP", "203.0.113.5"), "203.0.113.5"},
		{"all hops trusted: the peer itself", "10.244.0.7:4000", hdr("X-Forwarded-For", "10.244.0.9"), "10.244.0.7"},
		{"single trusted address form", "192.0.2.10:99", hdr("X-Forwarded-For", "203.0.113.4:5555"), "203.0.113.4"},
		{"ipv6 proxy and client", "[2001:db8::1]:443", hdr("X-Forwarded-For", "2001:db8:ffff::9, 2001:db8::2"), "2001:db8:ffff::9"},
		{"multiple header lines", "10.244.0.7:4000", hdr("X-Forwarded-For", "203.0.113.9", "X-Forwarded-For", "10.244.0.8"), "203.0.113.9"},
		{"ipv4-mapped peer is unmapped", "[::ffff:10.244.0.7]:4000", hdr("X-Forwarded-For", "203.0.113.9"), "203.0.113.9"},
	}
	for _, tc := range cases {
		trusted := ingress
		if tc.name == "no proxies configured: peer wins even with a header" {
			trusted = nil
		}
		if got := ClientIP(tc.remote, tc.header, trusted); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParseTrustedProxiesRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"10.244.0.0/40", "ingress", "10.0.0"} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
	got, err := ParseTrustedProxies([]string{"", "10.244.0.5/16"})
	if err != nil || len(got) != 1 || got[0].String() != "10.244.0.0/16" {
		t.Fatalf("got %v, %v", got, err)
	}
}
