// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"context"
	"strings"
	"testing"
	"time"
)

// DPR-023: trace mode dials addresses that DNS data chose (root hints, then
// each zone's glue). Those dials must pass the same SSRF guard as any resolved
// target: a delegation into loopback/private space is refused unless the test
// carries the audited allow_private_targets override.
func TestDNSTraceDelegationDialsAreSSRFGuarded(t *testing.T) {
	addr := loopbackResolver(t) // answers with data, which trace treats as authoritative
	prev := rootServers
	rootServers = []string{addr}
	t.Cleanup(func() { rootServers = prev })

	guarded, err := NewDNS(Config{Target: "example.com", Timeout: 2 * time.Second, Params: map[string]string{"mode": "trace"}})
	if err != nil {
		t.Fatalf("NewDNS: %v", err)
	}
	res, _ := guarded.Run(context.Background())
	if res.Success || !strings.Contains(res.Error, "SSRF guard") {
		t.Fatalf("a trace hop into loopback must be refused by the SSRF guard, got success=%v error=%q", res.Success, res.Error)
	}

	allowed, err := NewDNS(Config{Target: "example.com", Timeout: 2 * time.Second, Params: map[string]string{"mode": "trace", "allow_private_targets": "true"}})
	if err != nil {
		t.Fatalf("NewDNS (allowed): %v", err)
	}
	res2, _ := allowed.Run(context.Background())
	if !res2.Success {
		t.Fatalf("with allow_private_targets the loopback delegation must be traced, got %q", res2.Error)
	}
}

// RTP-24: a delegation trace must be able to start from operator-configured
// root hints, so it can run on an isolated/air-gapped network or against a
// private root instead of the baked IANA roots. The root_hints param carries
// them; unset, the trace still falls back to the baked roots.
func TestDNSTraceHonorsConfiguredRootHints(t *testing.T) {
	configuredRoot := loopbackResolver(t) // a fake root that answers authoritatively

	// Stand in for the baked IANA roots so the test never touches the network.
	// Capture and restore the package var once; each sub-case reassigns it.
	orig := rootServers
	t.Cleanup(func() { rootServers = orig })

	// Configured: with the baked roots emptied, the trace can only reach an
	// authoritative answer by honoring the configured root hint. (Before the
	// fix the param was ignored, the trace used the empty baked list, and this
	// failed with "no servers to query".)
	rootServers = nil
	configured, err := NewDNS(Config{Target: "example.com", Timeout: 2 * time.Second, Params: map[string]string{
		"mode":                  "trace",
		"allow_private_targets": "true", // the fake root is on loopback
		"root_hints":            configuredRoot,
	}})
	if err != nil {
		t.Fatalf("NewDNS (configured root hints): %v", err)
	}
	res, _ := configured.Run(context.Background())
	if !res.Success {
		t.Fatalf("configured root_hints must be honored: the trace should start at the configured fake root, got error %q", res.Error)
	}
	if trace := res.Attributes["probectl.dns.trace"]; !strings.HasPrefix(trace, ".") {
		t.Fatalf("the delegation path must start at the (configured) root, got trace %q", trace)
	}

	// Default: with no root_hints, the trace must fall back to the baked roots
	// (here a live stand-in for the IANA roots).
	rootServers = []string{configuredRoot}
	deflt, err := NewDNS(Config{Target: "example.com", Timeout: 2 * time.Second, Params: map[string]string{
		"mode":                  "trace",
		"allow_private_targets": "true",
	}})
	if err != nil {
		t.Fatalf("NewDNS (default roots): %v", err)
	}
	res2, _ := deflt.Run(context.Background())
	if !res2.Success {
		t.Fatalf("with no root_hints the trace must fall back to the baked IANA roots, got error %q", res2.Error)
	}
}
