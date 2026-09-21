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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
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

	// Agent transport (S-a9f9db46): object-artifact ingest consumes the SAME
	// injected fence as every other plane — never an ad-hoc per-call fence.
	ca, err := crypto.GenerateCA("fence-inventory-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("control", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, data := range map[string][]byte{"cert.pem": certPEM, "key.pem": keyPEM, "ca.pem": ca.CertPEM()} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	transport, err := agenttransport.New(
		filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem"),
		db.Pool(), nil, nil, log)
	if err != nil {
		t.Fatalf("agent transport construction: %v", err)
	}
	transport.WithWriterFence(rt.writerFence)
	if !transport.HasTenantWriteFence() {
		t.Error("agent transport artifact ingest is not protected by the tenant erasure fence")
	}

	// Anti-vacuous half: the inventory must be able to FAIL. A planted
	// unfenced store is caught by the same predicate the checklist uses.
	if flowstore.HasTenantWriteFence(flowstore.NewMemory()) {
		t.Error("planted unfenced flow store passed the fence predicate — the inventory can no longer fail")
	}
}
