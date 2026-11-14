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

	"github.com/ctlplne/probectl/internal/tenancy"
)

type dependencyPopulationSpan struct {
	phase       string
	started     time.Time
	elapsed     time.Duration
	queryFailed bool
	query       string
	args        []any
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
	span := &dependencyPopulationSpan{phase: "aliases", started: time.Now(), query: data.SQL, args: append([]any(nil), data.Args...)}
	if strings.Contains(data.SQL, "AS agent_id") {
		span.phase = "health"
	}
	trace.mu.Lock()
	trace.spans = append(trace.spans, span)
	trace.mu.Unlock()
	return context.WithValue(ctx, dependencyPopulationSpanKey{}, span)
}

// Failure-only instrumentation executes the same alias read after the timed
// product operation. Log numeric plan statistics, never SQL or bound values.
func explainFailedDependencyPopulation(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sc tenancy.Scope) {
	t.Helper()
	trace, ok := pool.Config().ConnConfig.Tracer.(*dependencyPopulationTrace)
	if !ok {
		return
	}
	trace.mu.Lock()
	var query string
	var args []any
	for _, span := range trace.spans {
		if span.phase == "aliases" {
			query, args = span.query, append([]any(nil), span.args...)
		}
	}
	trace.mu.Unlock()
	if query == "" {
		return
	}
	err := func() error {
		var body []byte
		if err := sc.Q.QueryRow(ctx, "EXPLAIN (ANALYZE,FORMAT JSON,TIMING FALSE,SUMMARY TRUE) "+query, args...).Scan(&body); err != nil {
			return err
		}
		var plans []map[string]any
		if err := json.Unmarshal(body, &plans); err != nil {
			return err
		}
		var logPlan func(map[string]any)
		logPlan = func(plan map[string]any) {
			if kind, ok := plan["Node Type"].(string); ok {
				t.Logf("source population alias plan: node=%s rows=%v loops=%v removed=%v cost=%v index=%v", kind, plan["Actual Rows"], plan["Actual Loops"], plan["Rows Removed by Filter"], plan["Total Cost"], plan["Index Name"])
			}
			if children, ok := plan["Plans"].([]any); ok {
				for _, child := range children {
					if child, ok := child.(map[string]any); ok {
						logPlan(child)
					}
				}
			}
		}
		for _, plan := range plans {
			t.Logf("source population alias explain: execution_ms=%v planning_ms=%v", plan["Execution Time"], plan["Planning Time"])
			if root, ok := plan["Plan"].(map[string]any); ok {
				logPlan(root)
			}
		}
		return nil
	}()
	if err != nil {
		t.Log("source population alias explain unavailable")
	}
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
