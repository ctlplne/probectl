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
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestOTLPFenceRuntime proves the production runtime hands OTLP ingest and API
// the fenced store while lifecycle capability discovery receives the concrete
// backend.
func TestOTLPFenceRuntime(t *testing.T) {
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
			otelStore:     otelstore.NewMemory(),
			ebpfStore:     ebpfstore.NewMemory(),
			endpointStore: endpointstore.NewMemory(),
		},
		nil,
	)
	t.Cleanup(rt.stop)
	if !otelstore.HasTenantWriteFence(rt.otelStore) {
		t.Fatal("production serve runtime exposed an unfenced OTLP Store")
	}
	if rt.lifecycleOTLPStore() == rt.otelStore {
		t.Fatal("lifecycle received the ingest-only OTLP write-fence decorator")
	}
	type subjectEraser interface {
		EraseSubject(
			context.Context,
			string,
			string,
		) (deleted, remaining int, err error)
	}
	if _, ok := rt.lifecycleOTLPStore().(subjectEraser); !ok {
		t.Fatal("lifecycle OTLP backend lost EraseSubject capability")
	}
}
