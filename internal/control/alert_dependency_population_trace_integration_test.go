// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dependencyPopulationSpan struct {
	phase       string
	started     time.Time
	elapsed     time.Duration
	queryFailed bool
}

type dependencyPopulationSpanKey struct{}
type dependencyPopulationTrace struct {
	mu    sync.Mutex
	spans []*dependencyPopulationSpan
}

// Observe only the product query. An in-band EXPLAIN would add a second
// planning operation to the freshness window being tested. Failure output
// contains phase/timing/status only, never SQL, bound values or credentials.
func (trace *dependencyPopulationTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.HasPrefix(data.SQL, "WITH requested AS (") {
		return ctx
	}
	span := &dependencyPopulationSpan{phase: "aliases", started: time.Now()}
	if strings.Contains(data.SQL, "AS agent_id") {
		span.phase = "health"
	}
	trace.mu.Lock()
	trace.spans = append(trace.spans, span)
	trace.mu.Unlock()
	return context.WithValue(ctx, dependencyPopulationSpanKey{}, span)
}

func (trace *dependencyPopulationTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if span, ok := ctx.Value(dependencyPopulationSpanKey{}).(*dependencyPopulationSpan); ok {
		trace.mu.Lock()
		span.elapsed, span.queryFailed = time.Since(span.started), data.Err != nil
		trace.mu.Unlock()
	}
}

func dependencyPopulationObservedPool(t *testing.T, original *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	trace := &dependencyPopulationTrace{}
	config := original.Config().Copy()
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if t.Failed() {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			for _, span := range trace.spans {
				t.Logf("source population diagnostic: phase=%s elapsed=%s query_failed=%t", span.phase, span.elapsed, span.queryFailed)
			}
		}
	})
	return pool
}
