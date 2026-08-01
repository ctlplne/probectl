// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestPathFenceRuntime proves the production runtime fences the concrete path
// backend beneath the write-behind batching wrapper while lifecycle receives
// the concrete deletion-capable store.
func TestPathFenceRuntime(t *testing.T) {
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

	memory := pathstore.NewMemory()
	batched := pathstore.NewBatchingSaver(
		memory,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Hour,
		32,
	)
	rt := newServeRuntime(
		&config.Config{},
		db,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&serveStores{
			flowStore:     flowstore.NewMemory(),
			pathStore:     batched,
			otelStore:     otelstore.NewMemory(),
			ebpfStore:     ebpfstore.NewMemory(),
			endpointStore: endpointstore.NewMemory(),
		},
		nil,
	)
	t.Cleanup(rt.stop)
	if !pathstore.HasTenantWriteFence(rt.pathStore) {
		t.Fatal("production serve runtime exposed an unfenced path backend")
	}
	if rt.lifecyclePathStore() == rt.pathStore {
		t.Fatal("lifecycle received the path batching/write-fence decorators")
	}
	type tenantDeleter interface {
		DeleteTenant(
			context.Context,
			string,
		) (deleted, remaining int, err error)
	}
	if _, ok := rt.lifecyclePathStore().(tenantDeleter); !ok {
		t.Fatal("lifecycle path backend lost DeleteTenant capability")
	}
}
