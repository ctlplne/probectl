package pipeline

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

// AsyncEnricher takes ASN/geo enrichment OFF the flow hot path (Sprint 15,
// SCALE-011). The inner enricher caches, but a cache MISS still cost a
// synchronous DNS lookup per record inside the consume loop. Now:
//
//   - HIT: the cached enrichment returns immediately (the only inline work).
//   - MISS: the address is queued for a small background worker pool to warm
//     and the CURRENT record proceeds UNENRICHED (ErrEnrichPending) — ingest
//     never blocks on a lookup. The next records for that address hit the
//     warmed cache.
//   - LAG: a full warm queue drops the warm request (counted) — graceful
//     degradation; enrichment quality dips, ingest throughput does not.
//
// The FlowConsumer already treats an enrichment error as "skip enrichment",
// so no consumer change is needed — this wrapper changes the latency model,
// not the contract.
type AsyncEnricher struct {
	inner   FlowEnricher
	log     *slog.Logger
	workers int

	mu    sync.Mutex
	cache map[string]asyncEntry
	ttl   time.Duration
	max   int

	warm chan string

	hits    atomic.Uint64
	misses  atomic.Uint64
	dropped atomic.Uint64 // warm requests shed by the full queue
	now     func() time.Time
}

type asyncEntry struct {
	e   opendata.Enrichment
	exp time.Time
}

// ErrEnrichPending marks a cache miss being warmed in the background — the
// caller proceeds without enrichment (the consumer's existing degrade path).
var ErrEnrichPending = errors.New("pipeline: enrichment warming (record proceeds unenriched)")

// NewAsyncEnricher wraps inner. Start the warm pool with Run.
func NewAsyncEnricher(inner FlowEnricher, log *slog.Logger) *AsyncEnricher {
	if log == nil {
		log = slog.Default()
	}
	return &AsyncEnricher{
		inner: inner, log: log, workers: 2,
		cache: map[string]asyncEntry{}, ttl: time.Hour, max: 65536,
		warm: make(chan string, 1024), now: time.Now,
	}
}

// Enrich implements FlowEnricher: cache hit inline, miss → background warm.
func (a *AsyncEnricher) Enrich(_ context.Context, addr string) (opendata.Enrichment, error) {
	a.mu.Lock()
	ent, ok := a.cache[addr]
	if ok && a.now().Before(ent.exp) {
		a.mu.Unlock()
		a.hits.Add(1)
		return ent.e, nil
	}
	a.mu.Unlock()
	a.misses.Add(1)
	select {
	case a.warm <- addr:
	default:
		a.dropped.Add(1) // enrichment lags: shed the warm, never the record
	}
	return opendata.Enrichment{}, ErrEnrichPending
}

// Run drains the warm queue with a small worker pool until ctx ends.
func (a *AsyncEnricher) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for i := 0; i < a.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case addr := <-a.warm:
					a.warmOne(ctx, addr)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func (a *AsyncEnricher) warmOne(ctx context.Context, addr string) {
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e, err := a.inner.Enrich(lctx, addr)
	if err != nil {
		return // the inner enricher degrades gracefully; retry on next miss
	}
	a.mu.Lock()
	if len(a.cache) >= a.max {
		a.cache = map[string]asyncEntry{} // bounded: reset, never grow (SCALE-003 stance)
	}
	a.cache[addr] = asyncEntry{e: e, exp: a.now().Add(a.ttl)}
	a.mu.Unlock()
}

// EnrichStats reports the cache behavior (hits/misses/shed warms).
func (a *AsyncEnricher) EnrichStats() (hits, misses, dropped uint64) {
	return a.hits.Load(), a.misses.Load(), a.dropped.Load()
}
