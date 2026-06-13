// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"io"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
)

// CODE-001: buildServeStores carries the store-construction phase that used to
// inline ~140 lines into run(), and returns ONE aggregate closer in place of the
// long defer chain. This test asserts (a) the all-memory profile builds, (b) the
// returned closer tears everything down without panicking, and (c) the bundle is
// fully populated — the closer-on-success path of the leak guarantee.
func TestBuildServeStoresBuildsAndClosesCleanly(t *testing.T) {
	cfg, err := config.Load(func(k string) string {
		// All planes in memory mode → no external infra, deterministic in CI.
		return map[string]string{
			"PROBECTL_BUS_MODE":       "memory",
			"PROBECTL_TSDB_MODE":      "memory",
			"PROBECTL_PATHSTORE_MODE": "memory",
			"PROBECTL_OTELSTORE_MODE": "memory",
			"PROBECTL_FLOWSTORE_MODE": "memory",
			"PROBECTL_EBPFSTORE_MODE": "memory",
		}[k]
	})
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	log := logging.New(io.Discard, "error", "json")

	st, closeStores, err := buildServeStores(cfg, log)
	if err != nil {
		t.Fatalf("buildServeStores (all-memory): %v", err)
	}
	if st == nil || closeStores == nil {
		t.Fatal("buildServeStores must return a bundle and a closer on success")
	}

	// Every plane the serve path consumes must be populated (a nil store would
	// nil-panic later in run()).
	if st.resultBus == nil {
		t.Error("resultBus is nil")
	}
	if st.tsdbWriter == nil {
		t.Error("tsdbWriter is nil")
	}
	if st.ingestWriter == nil {
		t.Error("ingestWriter is nil")
	}
	if st.pathStore == nil {
		t.Error("pathStore is nil")
	}
	if st.otelStore == nil {
		t.Error("otelStore is nil")
	}
	if st.flowStore == nil {
		t.Error("flowStore is nil")
	}
	if st.ebpfStore == nil {
		t.Error("ebpfStore is nil")
	}

	// The aggregate closer must run all teardowns without panicking, and be
	// idempotent enough to call once (it's invoked via defer in run()).
	closeStores()
}
