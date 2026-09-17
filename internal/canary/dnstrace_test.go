// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
