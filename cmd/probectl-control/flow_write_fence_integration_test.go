// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFlowFenceRuntime proves the real control-plane runtime hands the flow
// consumer/API surface the decorated store rather than leaving the fence as an
// unused helper around a test-only backend.
func TestFlowFenceRuntime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, testsupport.PostgresDSN(), 2, 0, time.Second)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}

	rt := newServeRuntime(
		&config.Config{},
		db,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&serveStores{flowStore: flowstore.NewMemory()},
		nil,
	)
	t.Cleanup(rt.stop)
	if !flowstore.HasTenantWriteFence(rt.flowStore) {
		t.Fatal("production serve runtime exposed an unfenced flow Store")
	}
}
