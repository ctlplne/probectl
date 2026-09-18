// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import "testing"

// DPR-154: path discovery traces to a HOST, and a test's target is whatever the
// operator created the test with — usually a URL. net.SplitHostPort is a
// host:port parser and nothing else; given a URL it returned the scheme, and the
// control plane went looking for a machine called "https".
func TestPathHostReducesATestTargetToAHost(t *testing.T) {
	for _, tc := range []struct{ name, target, want string }{
		// The case that broke J4 for every HTTP test in the lab.
		{"https url with a path", "https://example.com/checkout", "example.com"},
		{"http url", "http://example.com/", "example.com"},
		{"url with an explicit port", "http://198.51.100.10:8080/x", "198.51.100.10"},
		{"url with an ipv6 literal", "https://[2001:db8::1]:8443/x", "2001:db8::1"},
		{"host and port", "example.com:443", "example.com"},
		{"bracketed ipv6 and port", "[2001:db8::1]:443", "2001:db8::1"},
		{"bare host", "example.com", "example.com"},
		{"bare address", "198.51.100.10", "198.51.100.10"},
		{"surrounding space", "  example.com:443 ", "example.com"},
		// A target that is not a URL and not host:port is passed through
		// unchanged, so the resolver's own error names what the operator typed.
		{"nonsense", "not a target", "not a target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pathHost(tc.target); got != tc.want {
				t.Errorf("pathHost(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}
