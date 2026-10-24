// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7redact

import "testing"

// D-65: DNS question names under metadata. Default: labels left of the
// registered domain are templated with the route rules; regulated: only the
// registered domain (eTLD+1, from the compiled-in public-suffix list).
func TestDNSName(t *testing.T) {
	for _, tc := range []struct {
		in, templated, registered string
	}{
		{"48213.patients.example.com", "{id}.patients.example.com", "example.com"},
		{"48213.patients.example.com.", "{id}.patients.example.com", "example.com"},
		{"alice.users.corp.internal", "alice.users.corp.internal", "corp.internal"}, // the word-shaped gap
		{"api.example.com", "api.example.com", "example.com"},
		{"example.com", "example.com", "example.com"},
		{"x7k2q9.a1b2c3.tunnel.example.co.uk", "{id}.tunnel.example.co.uk", "example.co.uk"},
		{"MZXW6YTBOI.exfil.example.net", "{id}.exfil.example.net", "example.net"},
		{"user123.svc.cluster.local", "{id}.svc.cluster.local", "cluster.local"},
		{"localhost", "localhost", "localhost"},
	} {
		if got, _ := DNSName(tc.in, false); got != tc.templated {
			t.Errorf("DNSName(%q) = %q, want %q", tc.in, got, tc.templated)
		}
		if got, _ := DNSName(tc.in, true); got != tc.registered {
			t.Errorf("DNSName(%q, registered) = %q, want %q", tc.in, got, tc.registered)
		}
		if got, _ := DNSName(DNSNameOf(tc.in), false); got != DNSNameOf(tc.in) {
			t.Errorf("DNSName is not idempotent on %q: %q", tc.in, got)
		}
	}
	if got, _ := DNSName(`a"b.example.com`, false); got != Placeholder {
		t.Errorf("a name with non-DNS bytes = %q, want %q", got, Placeholder)
	}
}

// DNSNameOf is the default-profile templated name (a test helper).
func DNSNameOf(n string) string { out, _ := DNSName(n, false); return out }

func TestMinimizeDNSUnderMetadata(t *testing.T) {
	c := Call{Protocol: "dns", Method: "A", Resource: "48213.patients.example.com", Status: "NOERROR"}
	if got, _ := MinimizeWith(c, ModeMetadata, Options{}); got.Resource != "{id}.patients.example.com" {
		t.Fatalf("metadata DNS name = %q", got.Resource)
	}
	if got, _ := MinimizeWith(c, ModeMetadata, Options{DNSRegisteredDomainOnly: true}); got.Resource != "example.com" {
		t.Fatalf("regulated DNS name = %q", got.Resource)
	}
	if got, _ := MinimizeWith(c, ModeHeaders, Options{}); got.Resource != c.Resource {
		t.Fatalf("headers opt-in DNS name = %q, want it kept", got.Resource)
	}
}
