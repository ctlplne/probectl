// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package canary_test

import (
	"context"
	"testing"

	"time"

	"github.com/ctlplne/probectl/internal/testsupport"

	"github.com/ctlplne/probectl/internal/canary"
)

// TestICMPLoopback proves the S7 Done-when on a real socket: an ICMP probe to a
// loopback target produces correct loss/latency stats. It skips (not fails) where
// neither unprivileged datagram ICMP nor raw sockets are permitted.
func TestICMPLoopback(t *testing.T) {
	for _, target := range []string{"127.0.0.1", "::1"} {
		for _, payload := range []string{"56", "4096"} {
			t.Run(target+"/payload-"+payload, func(t *testing.T) {
				c, err := canary.NewICMP(canary.Config{
					Type: "icmp", Target: target, Timeout: 2 * time.Second,
					Params: map[string]string{"allow_private_targets": "true", "count": "3", "payload_bytes": payload},
				})
				if err != nil {
					t.Fatal(err)
				}
				res, err := c.Run(context.Background())
				if err != nil {
					testsupport.SkipOrFatal(t, "ICMP socket unavailable (need ping_group_range or CAP_NET_RAW): %v", err)
				}
				if !res.Success {
					testsupport.SkipOrFatal(t, "loopback %s unreachable in this environment: %s", target, res.Error)
				}
				if res.ICMP == nil || !res.ICMP.Complete() || res.ICMP.Transmitted != 3 || res.ICMP.Replies != 3 || res.Metrics["measurement.complete"] != 1 {
					t.Fatalf("real ICMP measurement did not retain the complete batch for %s payload %s: %+v", target, payload, res.ICMP)
				}
				if res.Metrics["packets.received"] < 1 {
					t.Fatalf("no replies from %s: %v", target, res.Metrics)
				}
				if res.Metrics["loss.ratio"] != 0 {
					t.Errorf("loopback loss = %v, want 0", res.Metrics["loss.ratio"])
				}
				if res.Metrics["rtt.avg.ms"] < 0 {
					t.Errorf("negative rtt: %v", res.Metrics)
				}
			})
		}
	}
}
