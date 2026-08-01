// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"testing"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// SCALE-001: the default prometheus ingest profile wraps the writer in a
// BatchingWriter (so it coalesces results instead of POSTing per result),
// while the read path keeps the concrete *tsdb.Prometheus for its gauge type
// assertion. This pins the wired-in default + the read-path contract.
func TestBuildIngestWriterDefaultsBatchedForPrometheus(t *testing.T) {
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"PROBECTL_DATABASE_URL": "postgres://probectl:test-only@localhost:5432/probectl?sslmode=require",
			"PROBECTL_TSDB_MODE":    "prometheus",
			"PROBECTL_TSDB_URL":     "https://prom.example.com:9090",
		}[k]
	})
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	if !cfg.RemoteWriteBatchEnabled {
		t.Fatal("prometheus default must enable remote-write batching (SCALE-001)")
	}

	raw, err := tsdb.NewWithLimits(cfg.TSDBMode, cfg.TSDBURL, 0, 0)
	if err != nil {
		t.Fatalf("tsdb: %v", err)
	}
	defer raw.Close()

	// The raw writer is the concrete *tsdb.Prometheus that the read/gauge path
	// type-asserts (registerLossGauges) — that assertion must still hold.
	if _, ok := raw.(*tsdb.Prometheus); !ok {
		t.Fatalf("expected raw prometheus writer to be *tsdb.Prometheus, got %T", raw)
	}

	ingest, closer := buildIngestWriter(cfg, raw)
	if closer != nil {
		defer func() { _ = closer() }()
	}
	// The INGEST writer must be the batching wrapper, not the raw writer.
	if _, ok := ingest.(*tsdb.BatchingWriter); !ok {
		t.Fatalf("default prometheus ingest writer must be *tsdb.BatchingWriter, got %T", ingest)
	}
	if closer == nil {
		t.Fatal("batching wrapper must return a closer so it flushes on shutdown")
	}
}

// With batching explicitly disabled the ingest path uses the raw writer
// unchanged (no wrapper, no closer) — the read-path concrete type is the same
// object.
func TestBuildIngestWriterUnbatchedWhenDisabled(t *testing.T) {
	raw, err := tsdb.New("memory", "")
	if err != nil {
		t.Fatalf("tsdb: %v", err)
	}
	defer raw.Close()
	cfg := &config.Config{RemoteWriteBatchEnabled: false}
	ingest, closer := buildIngestWriter(cfg, raw)
	if closer != nil {
		t.Fatal("no wrapper expected when batching is disabled")
	}
	if ingest != raw {
		t.Fatal("ingest writer should be the raw writer when batching is disabled")
	}
}
