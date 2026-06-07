package agenttransport

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"
)

// WIRE-006: the stream-envelope freshness/replay decision table.
func TestFreshnessReplayWindow(t *testing.T) {
	base := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)
	c := newNonceCache(10 * time.Minute)
	c.now = func() time.Time { return base }

	md := func(sentAt time.Time, nonce string) metadata.MD {
		return metadata.Pairs(
			FreshnessSentAtKey, strconv.FormatInt(sentAt.Unix(), 10),
			FreshnessNonceKey, nonce,
		)
	}

	// Fresh envelope: accepted.
	if err := c.check(md(base.Add(-time.Minute), "n1"), "t/a"); err != nil {
		t.Fatalf("fresh envelope refused: %v", err)
	}
	// REPLAY: the same nonce inside the window is refused.
	if err := c.check(md(base.Add(-time.Minute), "n1"), "t/a"); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed nonce must refuse, got %v", err)
	}
	// Another agent may use the same nonce value (scoped per agent).
	if err := c.check(md(base.Add(-time.Minute), "n1"), "t/b"); err != nil {
		t.Fatalf("nonce scope must be per agent: %v", err)
	}
	// STALE: outside the window (past) refused.
	if err := c.check(md(base.Add(-11*time.Minute), "n2"), "t/a"); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale envelope must refuse, got %v", err)
	}
	// FUTURE: badly skewed clock refused too.
	if err := c.check(md(base.Add(11*time.Minute), "n3"), "t/a"); err == nil {
		t.Fatal("future-skewed envelope must refuse")
	}
	// Missing metadata: fail closed.
	if err := c.check(metadata.MD{}, "t/a"); err == nil {
		t.Fatal("missing freshness metadata must refuse")
	}
	// Malformed timestamp: fail closed.
	if err := c.check(metadata.Pairs(FreshnessSentAtKey, "yesterday", FreshnessNonceKey, "n4"), "t/a"); err == nil {
		t.Fatal("malformed sent-at must refuse")
	}

	// The nonce expires OUT of the window and may then be reused (the window
	// is the replay horizon; reuse after it is just a fresh envelope).
	c.now = func() time.Time { return base.Add(11 * time.Minute) }
	if err := c.check(md(base.Add(10*time.Minute+30*time.Second), "n1"), "t/a"); err != nil {
		t.Fatalf("nonce reuse AFTER the window must be fine: %v", err)
	}
}

// The cache is bounded: an attacker cannot flush the replay horizon by
// flooding nonces — past the bound, new envelopes refuse instead of evicting.
func TestFreshnessNonceCacheBounded(t *testing.T) {
	base := time.Now()
	c := newNonceCache(10 * time.Minute)
	c.now = func() time.Time { return base }
	mk := func(n int) metadata.MD {
		return metadata.Pairs(
			FreshnessSentAtKey, strconv.FormatInt(base.Unix(), 10),
			FreshnessNonceKey, "flood-"+strconv.Itoa(n),
		)
	}
	for i := 0; i < noncesPerAgent; i++ {
		if err := c.check(mk(i), "t/a"); err != nil {
			t.Fatalf("fill %d: %v", i, err)
		}
	}
	if err := c.check(mk(noncesPerAgent+1), "t/a"); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("flooded cache must refuse rather than evict, got %v", err)
	}
}

// The agent-side helper attaches both keys.
func TestFreshnessMetadataAttach(t *testing.T) {
	ctx, err := FreshnessMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	if len(md.Get(FreshnessSentAtKey)) != 1 || len(md.Get(FreshnessNonceKey)) != 1 {
		t.Fatalf("metadata incomplete: %v", md)
	}
	if len(md.Get(FreshnessNonceKey)[0]) != 32 { // 16 bytes hex
		t.Fatalf("nonce length wrong: %q", md.Get(FreshnessNonceKey)[0])
	}
}
