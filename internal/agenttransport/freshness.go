package agenttransport

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Application-layer replay/freshness protection on ingestion (Sprint 12,
// WIRE-006). mTLS already authenticates the CHANNEL (TLS itself is
// replay-proof on the wire); this adds defense in depth at the APPLICATION
// layer: every results stream carries a sent-at timestamp + a random nonce as
// gRPC metadata INSIDE the authenticated channel — so a captured/duplicated
// stream open (e.g. replayed through a misbehaving proxy, or re-issued by a
// compromised middlebox holding connection state) is refused:
//
//   - sent-at outside the freshness window → stale, refused;
//   - a nonce this agent already used inside the window → replay, refused.
//
// Store-and-forward stays intact: the window bounds the STREAM ENVELOPE, not
// the result timestamps — buffered results from an outage replay fine over a
// fresh stream.
const (
	// FreshnessSentAtKey and FreshnessNonceKey are the metadata keys agents
	// attach when opening a results stream.
	FreshnessSentAtKey = "x-probectl-sent-at"
	FreshnessNonceKey  = "x-probectl-nonce"
	// DefaultFreshnessWindow bounds acceptable clock skew + transit delay for
	// the stream envelope.
	DefaultFreshnessWindow = 10 * time.Minute
	// noncesPerAgent bounds the per-agent replay cache (a results stream
	// opens at most every few seconds; 256 covers the window many times over).
	noncesPerAgent = 256
)

// FreshnessMetadata returns the outgoing-context metadata an agent attaches
// when opening a results stream.
func FreshnessMetadata(ctx context.Context) (context.Context, error) {
	nonce, err := crypto.Random(16)
	if err != nil {
		return nil, err
	}
	return metadata.AppendToOutgoingContext(ctx,
		FreshnessSentAtKey, strconv.FormatInt(time.Now().Unix(), 10),
		FreshnessNonceKey, hex.EncodeToString(nonce),
	), nil
}

// nonceCache remembers recently seen (agent, nonce) pairs inside the window.
type nonceCache struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]map[string]time.Time // agent -> nonce -> seen-at
	now    func() time.Time
}

func newNonceCache(window time.Duration) *nonceCache {
	if window <= 0 {
		window = DefaultFreshnessWindow
	}
	return &nonceCache{window: window, seen: map[string]map[string]time.Time{}, now: time.Now}
}

// check validates the envelope and records the nonce. Fail closed: missing
// metadata, stale timestamps, and repeated nonces all refuse.
func (c *nonceCache) check(md metadata.MD, agentKey string) error {
	sentAtVals := md.Get(FreshnessSentAtKey)
	nonceVals := md.Get(FreshnessNonceKey)
	if len(sentAtVals) == 0 || len(nonceVals) == 0 || nonceVals[0] == "" {
		return fmt.Errorf("missing freshness metadata (%s/%s) — agents from this release attach it; refuse rather than accept an unbounded-replay envelope", FreshnessSentAtKey, FreshnessNonceKey)
	}
	sentUnix, err := strconv.ParseInt(sentAtVals[0], 10, 64)
	if err != nil {
		return fmt.Errorf("malformed %s", FreshnessSentAtKey)
	}
	now := c.now()
	sent := time.Unix(sentUnix, 0)
	if d := now.Sub(sent); d > c.window || d < -c.window {
		return fmt.Errorf("stale stream envelope: sent %s, window ±%s (replayed or badly skewed clock)", sent.UTC().Format(time.RFC3339), c.window)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	agentSeen := c.seen[agentKey]
	if agentSeen == nil {
		agentSeen = map[string]time.Time{}
		c.seen[agentKey] = agentSeen
	}
	// Sweep expired + bound the cache before judging.
	for n, at := range agentSeen {
		if now.Sub(at) > c.window {
			delete(agentSeen, n)
		}
	}
	if _, dup := agentSeen[nonceVals[0]]; dup {
		return fmt.Errorf("replayed stream envelope (nonce reuse inside the freshness window)")
	}
	if len(agentSeen) >= noncesPerAgent {
		// Bounded: refuse rather than evict (an attacker should not be able
		// to flush the replay cache by flooding nonces).
		return fmt.Errorf("nonce cache exhausted for this agent (flood?); retry shortly")
	}
	agentSeen[nonceVals[0]] = now
	return nil
}
