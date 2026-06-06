//go:build isolation

package pathstore

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/path"
)

// U-026: the cross-tenant isolation gate against REAL ClickHouse for the
// path store. Runs in CI (containerized CH via PROBECTL_PATHSTORE_URL);
// skips locally when unset.
func TestClickHousePathCrossTenantIsolation(t *testing.T) {
	url := os.Getenv("PROBECTL_PATHSTORE_URL")
	if url == "" {
		t.Skip("PROBECTL_PATHSTORE_URL not set — ClickHouse isolation gate runs in CI")
	}
	c, err := NewClickHouse(url)
	if err != nil {
		t.Fatalf("clickhouse: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ta := fmt.Sprintf("path-iso-a-%d", now.UnixNano())
	tb := fmt.Sprintf("path-iso-b-%d", now.UnixNano())
	target := fmt.Sprintf("shared-target-%d.example", now.UnixNano())

	mk := func(ip string) *path.Path {
		return &path.Path{
			Target: target, TargetIP: ip, Mode: "icmp", MaxHops: 8, TraceCount: 1, DestinationReached: true,
			Hops: []path.Hop{{TTL: 1, Nodes: []path.HopNode{{IP: ip, Sent: 1, Received: 1, RTTAvgMs: 1.5}}}},
		}
	}
	if err := c.Save(ctx, ta, mk("198.51.100.10")); err != nil {
		t.Fatalf("save A: %v", err)
	}
	if err := c.Save(ctx, tb, mk("192.0.2.99")); err != nil {
		t.Fatalf("save B: %v", err)
	}

	// Tenant A's latest path for the SHARED target name must be A's, never B's.
	got, ok, err := c.Latest(ctx, ta, target)
	if err != nil || !ok {
		t.Fatalf("latest A: ok=%v err=%v", ok, err)
	}
	if got.TargetIP != "198.51.100.10" {
		t.Fatalf("CROSS-TENANT LEAK: tenant A read %q", got.TargetIP)
	}

	// The empty-tenant refusal (defense in depth) holds on the live store too.
	if _, _, err := c.Latest(ctx, "", target); err == nil {
		t.Fatal("unscoped Latest must refuse (ErrNoTenant)")
	}
}
