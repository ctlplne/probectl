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
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

// TestTSDBFenceRuntime proves the production runtime keeps its concrete TSDB
// for query/lifecycle/global metrics while fencing both tenant write entry
// points: bus-ingest batching and the Prometheus remote-write API.
func TestTSDBFenceRuntime(t *testing.T) {
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

	raw := tsdb.NewMemory()
	batched := tsdb.NewBatchingWriter(raw, 32, time.Hour)
	rt := newServeRuntime(
		&config.Config{},
		db,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&serveStores{
			tsdbWriter:   raw,
			ingestWriter: batched,
		},
		nil,
	)
	t.Cleanup(rt.stop)

	if rt.tsdbWriter != raw {
		t.Fatal("query/lifecycle/global TSDB path lost its concrete backend")
	}
	if tsdb.HasTenantWriteFence(rt.tsdbWriter) {
		t.Fatal("concrete query/lifecycle/global TSDB path was replaced by a tenant writer")
	}
	if !tsdb.HasTenantWriteFence(rt.ingestWriter) {
		t.Fatal("production bus-ingest TSDB writer is not fenced")
	}
	if !tsdb.HasTenantWriteFence(rt.tenantTSDBWriter) {
		t.Fatal("production Prometheus remote-write seam is not fenced")
	}
	if tsdb.UnderlyingWriter(rt.ingestWriter) != raw {
		t.Fatal("bus-ingest fencing no longer reaches the configured concrete TSDB")
	}
	if tsdb.UnderlyingWriter(rt.tenantTSDBWriter) != raw {
		t.Fatal("remote-write fencing no longer reaches the configured concrete TSDB")
	}
}
