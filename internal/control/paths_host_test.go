// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
)

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

// DPR-157: path discovery starts by resolving the test's target, so an
// unresolvable target is the first thing an operator hits — and it was reported
// as a 500. "The product is broken" and "your target does not resolve" send
// people to different places.
func TestUnresolvableTargetIsNotAnInternalError(t *testing.T) {
	// What net.ResolveIPAddr returns for a name that does not exist, wrapped
	// exactly as internal/path wraps it.
	err := pathDiscoveryError("nowhere.invalid", fmt.Errorf("path: resolve nowhere.invalid: %w", &net.DNSError{
		Err: "no such host", Name: "nowhere.invalid", IsNotFound: true,
	}))
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("want a domain error, got %T: %v", err, err)
	}
	if apiErr.Kind == apierror.KindInternal {
		t.Errorf("an unresolvable target is still reported as an internal error: %v", apiErr)
	}
	if !strings.Contains(apiErr.Message, "nowhere.invalid") {
		t.Errorf("the message does not name the target, so it is not actionable: %q", apiErr.Message)
	}
	// Message is what the caller receives; the wrapped cause stays in the log,
	// because the resolver's own text names the deployment's nameserver.
	if strings.Contains(apiErr.Message, "no such host") {
		t.Errorf("the resolver's raw text reached the caller: %q", apiErr.Message)
	}
	if !strings.Contains(apiErr.Error(), "no such host") {
		t.Error("the cause was dropped, so the log cannot say why it failed")
	}
}

// Anything that is NOT a resolution failure stays an internal error: a timeout
// or a socket permission problem really is the deployment's business.
func TestOtherDiscoveryFailuresStayInternal(t *testing.T) {
	err := pathDiscoveryError("198.51.100.10", errors.New("listen ip4:icmp: operation not permitted"))
	var apiErr *apierror.Error
	if !errors.As(err, &apiErr) || apiErr.Kind != apierror.KindInternal {
		t.Fatalf("want an internal error, got %v", err)
	}
}
