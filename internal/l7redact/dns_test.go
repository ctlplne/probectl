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
		// D-65 R1: the PSL private section is not a registered-domain boundary.
		{"bucket-patient-48213.s3.amazonaws.com", "{id}.s3.amazonaws.com", "amazonaws.com"},
		{"acct48213.blob.core.windows.net", "{id}.blob.core.windows.net", "windows.net"},
		{"cust-48213.azurewebsites.net", "{id}.azurewebsites.net", "azurewebsites.net"},
		{"patient-48213.github.io", "{id}.github.io", "github.io"},
		{"jdoe.herokuapp.com", "jdoe.herokuapp.com", "herokuapp.com"}, // the word-shaped gap
		// ... nor is a TLD the ICANN list does not know.
		{"w56hzv-23-c-0123.internal", "{id}.internal", "{id}.internal"},
		{"records-48213.corp", "{id}.corp", "{id}.corp"},
		{"host48213.local", "{id}.local", "{id}.local"},
		{"mrn48213.lan", "{id}.lan", "{id}.lan"},
		{"patient-48213.records.internal", "{id}.records.internal", "records.internal"},
		// D-68 (pending): an identifier-shaped ICANN registered label is kept.
		{"48213.com", "48213.com", "48213.com"},
		{"x1y2.a1b2.internal", "{id}.internal", "{id}.internal"},
	} {
		if got, _ := DNSName(tc.in, false); got != tc.templated {
			t.Errorf("DNSName(%q) = %q, want %q", tc.in, got, tc.templated)
		}
		if got, _ := DNSName(tc.in, true); got != tc.registered {
			t.Errorf("DNSName(%q, registered) = %q, want %q", tc.in, got, tc.registered)
		}
		if got, _ := DNSName(tc.registered, true); got != tc.registered {
			t.Errorf("DNSName is not idempotent on the registered form %q: %q", tc.registered, got)
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

func FuzzDNSName(f *testing.F) {
	for _, s := range []string{"48213.patients.example.com", "bucket-1.s3.amazonaws.com", "w56hzv-23-c-0123.internal", "a.b", "", "x.y.z.co.uk."} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, s string, registered bool) {
		out, _ := DNSName(s, registered)
		if len(out) > maxDNSName {
			t.Fatalf("unbounded: %d", len(out))
		}
		if again, _ := DNSName(out, registered); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}
