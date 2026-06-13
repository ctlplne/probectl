// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ai

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Remote-model resilience (AIRCA-004): a slow or down provider must degrade
// RCA gracefully, never take it down. ResilientModel wraps the REMOTE
// adapter with:
//
//   - a circuit breaker (internal/breaker, U-078): after consecutive
//     failures, calls short-circuit instead of stacking timeouts;
//   - a per-call timeout (the configured model timeout, ctx-enforced here
//     regardless of the adapter's own client settings);
//   - a response cache: identical question+evidence within the TTL is
//     answered without a provider round-trip. Evidence IDs are
//     session-random (U-037), so entries are keyed on CONTENT and citations
//     are remapped positionally onto the current session's IDs — grounding
//     still validates against real evidence;
//   - graceful degradation: on breaker-open, timeout, or provider error the
//     air-gapped BUILTIN model answers instead, clearly marked — the
//     Synthesis carries Degraded=true and the root cause is prefixed with a
//     partial-result banner. An answer always comes back.
//
// The local/builtin default path never gets wrapped (nothing to break).
type ResilientModel struct {
	remote   ModelAdapter
	fallback ModelAdapter
	br       *breaker.Breaker
	timeout  time.Duration
	cache    *synthCache

	degraded  atomic.Uint64 // fallback answers served (observability)
	cacheHits atomic.Uint64
}

// Resilience defaults (documented in docs/ai-egress.md). The breaker opens
// after breakerThreshold consecutive provider failures and re-probes after
// breakerCooldown; cached answers live for cacheTTL.
const (
	breakerThreshold = 3
	breakerCooldown  = 30 * time.Second
	cacheTTL         = 10 * time.Minute
	cacheMaxEntries  = 256
)

// NewResilientModel wraps remote with breaker+timeout+cache+fallback.
// timeout <= 0 disables the wrapper-level deadline (the adapter's own client
// timeout still applies).
func NewResilientModel(remote, fallback ModelAdapter, timeout time.Duration) *ResilientModel {
	return &ResilientModel{
		remote:   remote,
		fallback: fallback,
		br:       breaker.New(breakerThreshold, breakerCooldown),
		timeout:  timeout,
		cache:    newSynthCache(cacheMaxEntries, cacheTTL),
	}
}

// Name reports the remote adapter (provenance; a degraded answer SAYS it was
// answered by the builtin in its banner and Degraded flag).
func (m *ResilientModel) Name() string { return m.remote.Name() }

// RemoteEgress / Endpoint forward the inner adapter's egress posture so the
// U-013 consent gate keeps applying (cache hits and fallbacks serve
// remote-derived or remote-configured content — the strict reading stands).
func (m *ResilientModel) RemoteEgress() bool {
	if rm, ok := m.remote.(RemoteEgresser); ok {
		return rm.RemoteEgress()
	}
	return false
}

// Endpoint forwards the inner adapter's endpoint (audit provenance).
func (m *ResilientModel) Endpoint() string {
	if rm, ok := m.remote.(RemoteEgresser); ok {
		return rm.Endpoint()
	}
	return ""
}

// Degradations reports how many answers fell back to the builtin.
func (m *ResilientModel) Degradations() uint64 { return m.degraded.Load() }

// CacheHits reports answers served without a provider round-trip.
func (m *ResilientModel) CacheHits() uint64 { return m.cacheHits.Load() }

// Synthesize: cache → breaker(remote with timeout) → builtin fallback.
func (m *ResilientModel) Synthesize(ctx context.Context, in SynthesisInput) (Synthesis, error) {
	key := synthKey(ctx, m.remote.Name(), in)
	if syn, ok := m.cache.get(key, in); ok {
		m.cacheHits.Add(1)
		return syn, nil
	}

	var syn Synthesis
	err := m.br.Do(func() error {
		tctx := ctx
		if m.timeout > 0 {
			var cancel context.CancelFunc
			tctx, cancel = context.WithTimeout(ctx, m.timeout)
			defer cancel()
		}
		var serr error
		syn, serr = m.remote.Synthesize(tctx, in)
		return serr
	})
	if err == nil {
		m.cache.put(key, in, syn)
		return syn, nil
	}

	// Degrade: the air-gapped builtin answers, clearly marked (AIRCA-004).
	fsyn, ferr := m.fallback.Synthesize(ctx, in)
	if ferr != nil {
		return Synthesis{}, err // fallback itself failed: surface the ORIGINAL provider error
	}
	m.degraded.Add(1)
	fsyn.Degraded = true
	reason := "provider error"
	switch {
	case err == breaker.ErrOpen:
		reason = "provider circuit open"
	case ctx.Err() != nil || isDeadline(err):
		reason = "provider timeout"
	}
	fsyn.RootCause = "PARTIAL RESULT — remote model unavailable (" + reason +
		"); answered by the air-gapped builtin synthesizer: " + fsyn.RootCause
	return fsyn, nil
}

// Complete guards the generic chat seam (test authoring) with the SAME
// breaker — one provider, one health view. No cache (prompts are unique) and
// no builtin fallback (the authoring engine has its own heuristic fallback
// and 503 path).
func (m *ResilientModel) Complete(ctx context.Context, system, user string) (string, error) {
	rc, ok := m.remote.(RemoteCompleter)
	if !ok {
		return "", ErrEgressDenied // not a chat-capable adapter
	}
	var out string
	err := m.br.Do(func() error {
		tctx := ctx
		if m.timeout > 0 {
			var cancel context.CancelFunc
			tctx, cancel = context.WithTimeout(ctx, m.timeout)
			defer cancel()
		}
		var cerr error
		out, cerr = rc.Complete(tctx, system, user)
		return cerr
	})
	return out, err
}

func isDeadline(err error) bool {
	return err == context.DeadlineExceeded || (err != nil && err.Error() != "" &&
		(context.DeadlineExceeded.Error() == err.Error()))
}

// --- response cache (content-keyed, citation-remapping) ---

type cacheEntry struct {
	syn Synthesis
	ids []string // the evidence IDs the cached synthesis cites (positional)
	at  time.Time
}

type synthCache struct {
	mu         sync.Mutex
	entries    map[string]cacheEntry
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
}

func newSynthCache(maxEntries int, ttl time.Duration) *synthCache {
	return &synthCache{entries: map[string]cacheEntry{}, maxEntries: maxEntries, ttl: ttl, now: time.Now}
}

// synthKey hashes the tenant + model + question + evidence CONTENT in order —
// deliberately excluding the session-random evidence IDs (U-037), so the
// same question over the same signals hits across sessions. Hashing routes
// through internal/crypto (guardrail 3 — FIPS-swappable).
//
// AIRCA-001: the tenant ID is the FIRST component of the key so two tenants
// asking the identical question over identical evidence can never collide on a
// cache entry (defense-in-depth above the egress/RBAC gates — fail closed if
// the tenant is somehow absent by keying on an explicit empty sentinel that
// only ever collides with itself). The cache is process-wide and shared across
// tenants, so without this prefix a future content-key change could bleed one
// tenant's synthesized answer to another.
func synthKey(ctx context.Context, model string, in SynthesisInput) string {
	tenant := ""
	if id, ok := tenancy.FromContext(ctx); ok {
		tenant = id.String()
	}
	var b bytes.Buffer
	b.WriteString(tenant)
	b.WriteByte(0)
	b.WriteString(model)
	b.WriteByte(0)
	b.WriteString(in.Question)
	for _, e := range in.Evidence {
		b.WriteByte(0)
		b.WriteString(string(e.Domain))
		b.WriteByte(1)
		b.WriteString(e.Plane)
		b.WriteByte(1)
		b.WriteString(e.Severity)
		b.WriteByte(1)
		b.WriteString(e.Title)
		b.WriteByte(1)
		b.WriteString(e.Summary)
		b.WriteByte(1)
		b.WriteString(e.OccurredAt.UTC().Format(time.RFC3339))
	}
	return hex.EncodeToString(crypto.Hash(b.Bytes()))
}

// get returns the cached synthesis with citations REMAPPED onto the current
// session's evidence IDs. The key covers content in order, so position i in
// the cached run is position i now.
func (c *synthCache) get(key string, in SynthesisInput) (Synthesis, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || c.now().Sub(e.at) > c.ttl {
		if ok {
			delete(c.entries, key)
		}
		return Synthesis{}, false
	}
	if len(e.ids) != len(in.Evidence) {
		return Synthesis{}, false // shape drift: treat as miss
	}
	remap := make(map[string]string, len(e.ids))
	for i, old := range e.ids {
		remap[old] = in.Evidence[i].ID
	}
	return remapSynthesis(e.syn, remap), true
}

func (c *synthCache) put(key string, in SynthesisInput, syn Synthesis) {
	ids := make([]string, len(in.Evidence))
	for i, e := range in.Evidence {
		ids[i] = e.ID
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxEntries {
		// Evict the oldest (bounded scan; maxEntries is small).
		var oldestK string
		var oldestT time.Time
		first := true
		for k, e := range c.entries {
			if first || e.at.Before(oldestT) {
				oldestK, oldestT, first = k, e.at, false
			}
		}
		delete(c.entries, oldestK)
	}
	c.entries[key] = cacheEntry{syn: deepCopySynthesis(syn), ids: ids, at: c.now()}
}

// remapSynthesis deep-copies syn with every citation translated through
// remap (citations to unknown IDs pass through unchanged and die in
// grounding — fail closed).
func remapSynthesis(syn Synthesis, remap map[string]string) Synthesis {
	out := deepCopySynthesis(syn)
	for i := range out.RootCauseCitations {
		if id, ok := remap[out.RootCauseCitations[i].EvidenceID]; ok {
			out.RootCauseCitations[i].EvidenceID = id
		}
	}
	for i := range out.Findings {
		for j := range out.Findings[i].Citations {
			if id, ok := remap[out.Findings[i].Citations[j].EvidenceID]; ok {
				out.Findings[i].Citations[j].EvidenceID = id
			}
		}
	}
	return out
}

func deepCopySynthesis(syn Synthesis) Synthesis {
	out := syn
	out.RootCauseCitations = append([]Citation(nil), syn.RootCauseCitations...)
	out.Findings = make([]Finding, len(syn.Findings))
	for i, f := range syn.Findings {
		f.Citations = append([]Citation(nil), f.Citations...)
		out.Findings[i] = f
	}
	return out
}
