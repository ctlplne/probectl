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

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/endpointstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
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
}
