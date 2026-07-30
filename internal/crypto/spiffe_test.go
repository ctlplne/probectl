// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import "testing"

func TestSPIFFERoundTrip(t *testing.T) {
	uri := AgentSPIFFEID("tenant-123", "agent-abc")
	const want = "spiffe://probectl/tenant/tenant-123/agent/agent-abc"
	if uri != want {
		t.Fatalf("AgentSPIFFEID = %q, want %q", uri, want)
	}
	id, err := ParseSPIFFEID(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id.TrustDomain != "probectl" || id.TenantID != "tenant-123" || id.AgentID != "agent-abc" {
		t.Errorf("parsed = %+v", id)
	}
	if id.String() != uri {
		t.Errorf("String() = %q, want %q", id.String(), uri)
	}
}

func TestParseSPIFFEIDErrors(t *testing.T) {
	bad := []string{
		"https://probectl/tenant/x/agent/y", // wrong scheme
		"spiffe://probectl/org/x/agent/y",   // wrong segment label
		"spiffe://probectl/tenant/x",        // too short
		"spiffe://probectl/tenant//agent/y", // missing tenant identity
		"spiffe://probectl/tenant/x/agent/", // missing agent identity
	}
	for _, b := range bad {
		if _, err := ParseSPIFFEID(b); err == nil {
			t.Errorf("ParseSPIFFEID(%q) should fail", b)
		}
	}
}

func TestParseSPIFFEIDRejectsAmbiguousComponents(t *testing.T) {
	const canonical = "spiffe://probectl/tenant/t1/agent/a1"
	for name, uri := range map[string]string{
		"userinfo":       "spiffe://operator@probectl/tenant/t1/agent/a1",
		"query":          canonical + "?tenant=t2",
		"empty query":    canonical + "?",
		"fragment":       canonical + "#shadow",
		"empty fragment": canonical + "#",
		"escaped path":   "spiffe://probectl/tenant/t%31/agent/a1",
		"raw space":      "spiffe://probectl/tenant/t 1/agent/a1",
		"dot tenant":     "spiffe://probectl/tenant/./agent/a1",
		"dot-dot agent":  "spiffe://probectl/tenant/t1/agent/..",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSPIFFEID(uri); err == nil {
				t.Fatalf("ParseSPIFFEID(%q) accepted an ambiguous identity", uri)
			}
		})
	}
	if _, err := ParseSPIFFEID(canonical); err != nil {
		t.Fatalf("canonical identity rejected: %v", err)
	}
}
