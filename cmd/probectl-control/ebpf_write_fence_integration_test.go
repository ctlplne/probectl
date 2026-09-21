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
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestEBPFFenceRuntime proves the real control-plane runtime hands the eBPF
// ingest/API surfaces the decorated store instead of leaving the fence as an
// unused helper around a test-only backend.
func TestEBPFFenceRuntime(t *testing.T) {
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
		&serveStores{
			flowStore:     flowstore.NewMemory(),
			ebpfStore:     ebpfstore.NewMemory(),
			endpointStore: endpointstore.NewMemory(),
		},
		nil,
	)
	t.Cleanup(rt.stop)
	if !ebpfstore.HasTenantWriteFence(rt.ebpfStore) {
		t.Fatal("production serve runtime exposed an unfenced eBPF Store")
	}
	if rt.lifecycleEBPFStore() == rt.ebpfStore {
		t.Fatal("lifecycle received the ingest-only eBPF write-fence decorator")
	}
	type subjectDeleter interface {
		DeleteSubject(
			context.Context,
			string,
			string,
		) (deleted, remaining int64, err error)
	}
	if _, ok := rt.lifecycleEBPFStore().(subjectDeleter); !ok {
		t.Fatal("lifecycle eBPF backend lost DeleteSubject capability")
	}
}
