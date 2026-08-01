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
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/topology"
)

// TestTenantEraseMultiPlaneWriteFenceInventory is the coordinated parent
// regression for DATA-7683e96d. Per-plane tests prove lease behavior with two
// tenants; this test proves the production runtime cannot accidentally hand an
// unfenced concrete writer to one of those planes.
func TestTenantEraseMultiPlaneWriteFenceInventory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	db, err := store.Open(ctx, testsupport.PostgresDSN(), 4, 0, time.Second)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(db.Close)
	if err := db.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rawTSDB := tsdb.NewMemory()
	batchedTSDB := tsdb.NewBatchingWriter(rawTSDB, 32, time.Hour)
	rt := newServeRuntime(
		&config.Config{TopologyEngine: "memory"},
		db,
		log,
		&serveStores{
			tsdbWriter:    rawTSDB,
			ingestWriter:  batchedTSDB,
			pathStore:     pathstore.NewMemory(),
			otelStore:     otelstore.NewMemory(),
			flowStore:     flowstore.NewMemory(),
			ebpfStore:     ebpfstore.NewMemory(),
			endpointStore: endpointstore.NewMemory(),
		},
		nil,
	)
	t.Cleanup(rt.stop)
	if err := rt.buildServeEngines(); err != nil {
		t.Fatalf("build serve engines: %v", err)
	}

	checks := map[string]bool{
		"flow":                  flowstore.HasTenantWriteFence(rt.flowStore),
		"endpoint":              endpointstore.HasTenantWriteFence(rt.endpointStore),
		"ebpf":                  ebpfstore.HasTenantWriteFence(rt.ebpfStore),
		"otlp":                  otelstore.HasTenantWriteFence(rt.otelStore),
		"path":                  pathstore.HasTenantWriteFence(rt.pathStore),
		"tsdb bus ingest":       tsdb.HasTenantWriteFence(rt.ingestWriter),
		"tsdb remote write API": tsdb.HasTenantWriteFence(rt.tenantTSDBWriter),
		"topology":              topology.HasTenantWriteFence(rt.topoStore),
	}
	for plane, fenced := range checks {
		if !fenced {
			t.Errorf("production %s writer is not protected by the tenant erasure fence", plane)
		}
	}
	if rt.writerFence == nil {
		t.Error("production runtime has no deployment-wide tenant writer fence")
	}
	if rt.tsdbWriter != rawTSDB || tsdb.HasTenantWriteFence(rt.tsdbWriter) {
		t.Error("query/lifecycle/global TSDB path must remain the concrete backend outside tenant-write fencing")
	}
}
