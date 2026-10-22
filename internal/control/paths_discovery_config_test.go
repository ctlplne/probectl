// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import "testing"

// DPR-286: API path discovery asks for a raw-socket trace, so a control plane
// granted CAP_NET_RAW reports every hop; without the capability the tracer
// falls back to the unprivileged socket on its own.
func TestPathDiscoveryPrefersRawTracing(t *testing.T) {
	cfg := pathDiscoveryConfig("192.0.2.10")
	if !cfg.Privileged {
		t.Fatal("API path discovery does not request raw tracing: CAP_NET_RAW would never yield per-hop paths")
	}
	if cfg.Target != "192.0.2.10" || cfg.Mode != "icmp" || cfg.MaxHops != 30 || cfg.TraceCount != 3 {
		t.Fatalf("discovery config changed shape: %+v", cfg)
	}
}
