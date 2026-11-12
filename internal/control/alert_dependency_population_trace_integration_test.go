// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type dependencyPopulationSpan struct {
	phase                   string
	started                 time.Time
	elapsed                 time.Duration
	cost                    float64
	rows                    int64
	jit                     json.RawMessage
	planFailed, queryFailed bool
}

type dependencyPopulationSpanKey struct{}
type dependencyPopulationTrace struct {
	mu    sync.Mutex
	spans []*dependencyPopulationSpan
}

// EXPLAIN without ANALYZE records the fresh plan, without executing a second
// source read. Only phase/cost/row/JIT metadata is printed, and only on failure;
// SQL, bound source values and credentials never enter the output.
func (trace *dependencyPopulationTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.HasPrefix(data.SQL, "WITH requested AS (") {
		return ctx
	}
	span := &dependencyPopulationSpan{phase: "aliases", started: time.Now()}
	if strings.Contains(data.SQL, "AS agent_id") {
		span.phase = "health"
	}
	var raw []byte
	err := conn.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+data.SQL, data.Args...).Scan(&raw)
	var plan []struct {
		Plan struct {
			Cost float64 `json:"Total Cost"`
			Rows int64   `json:"Plan Rows"`
		} `json:"Plan"`
		JIT json.RawMessage `json:"JIT"`
	}
	span.planFailed = err != nil || json.Unmarshal(raw, &plan) != nil || len(plan) != 1
	if !span.planFailed {
		span.cost, span.rows, span.jit = plan[0].Plan.Cost, plan[0].Plan.Rows, plan[0].JIT
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
				t.Logf("source population diagnostic: phase=%s elapsed=%s cost=%g estimated_rows=%d jit=%s plan_failed=%t query_failed=%t",
					span.phase, span.elapsed, span.cost, span.rows, span.jit, span.planFailed, span.queryFailed)
			}
		}
	})
	return pool
}
