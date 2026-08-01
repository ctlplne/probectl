// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ai

import (
	"strings"
	"testing"
)

// TestRedactionFieldClassesCrossingTheBoundary pins the DEFAULT remote-egress
// policy: for every class of value probectl knows how to recognize, does it
// cross to a remote model verbatim or not?
//
// This is deliberately a whole-table assertion rather than a set of scattered
// per-class cases. The hostname default was flipped to masked (S-e5e1b903)
// because "kept by default" had never actually been decided — it was inherited.
// A table that enumerates the entire boundary means the next person changing any
// class has to change this table, and changing this table is a decision.
func TestRedactionFieldClassesCrossingTheBoundary(t *testing.T) {
	cases := []struct {
		class   string
		sample  string
		crosses bool   // true = the literal value reaches the remote model
		why     string // the reason the decision is what it is
	}{
		{"pem block", "-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN\n-----END PRIVATE KEY-----", false,
			"a private key crossing any boundary is unconditionally wrong"},
		{"bearer token", "Authorization: Bearer sk-live-abcdef123456789", false,
			"a credential is a credential regardless of policy"},
		{"kv credential", "api_key=AKxyzSECRET9", false,
			"same, in the shape config files and log lines actually use"},
		{"aws access key id", "AKIAIOSFODNN7EXAMPLE", false,
			"names a real account; pairs with a secret that may be elsewhere in the prompt"},
		{"ipv4", "10.1.2.3", false,
			"addressing plan is topology; masked deterministically so correlation survives"},
		{"ipv4 prefix", "192.168.7.0/24", false,
			"a prefix discloses more than a host, not less"},
		{"ipv6", "2001:db8::1", false,
			"same reasoning as v4"},
		{"hostname", "payments-db-3.prod.acme.internal", false,
			"an internal FQDN is a service inventory, an environment map and often a tenant name"},
		{"email", "oncall@acme.example.com", false,
			"PII, and the domain is itself an org identifier"},
		{"mac", "aa:bb:cc:dd:ee:ff", false,
			"a durable hardware identifier"},
		{"phone", "+1 555-010-1234", false,
			"PII"},
		{"free prose", "packet loss rose sharply after the maintenance window", true,
			"the question itself must cross or there is nothing to answer"},
		{"metric names and numbers", "p99_latency_ms 412 over 15m", true,
			"measurements are the evidence; they carry no identity"},
		{"as number", "AS64512", true,
			"routing context the model needs; public, not tenant-identifying"},
	}

	for _, tc := range cases {
		t.Run(tc.class, func(t *testing.T) {
			got := redactTextForTenant(tc.sample, DefaultRedaction, "tenant-a")
			crossed := strings.Contains(got, tc.sample)
			if crossed != tc.crosses {
				verb := "crossed the boundary verbatim"
				if !crossed {
					verb = "was masked"
				}
				t.Fatalf("class %q %s (want crosses=%v, because %s)\n  in:  %q\n  out: %q",
					tc.class, verb, tc.crosses, tc.why, tc.sample, got)
			}
		})
	}
}

// TestDefaultRedactionMasksHostnames states the decision on its own, so it fails
// loudly and by name if the default is ever flipped back without also revisiting
// docs/ai-egress.md.
func TestDefaultRedactionMasksHostnames(t *testing.T) {
	if !DefaultRedaction.MaskHostnames {
		t.Fatal("DefaultRedaction.MaskHostnames is false: internal FQDNs would reach remote models verbatim. " +
			"If this is intended, change docs/ai-egress.md \"Why hostnames are masked by default\" first")
	}
	if !DefaultRedaction.MaskIPs || !DefaultRedaction.MaskPII {
		t.Fatal("DefaultRedaction must mask IPs and PII by default")
	}
}
