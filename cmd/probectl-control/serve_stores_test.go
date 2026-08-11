// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/promapi"
)

func TestDatastoreBasicAuthClientOnlyLoadsForEnabledBackend(t *testing.T) {
	factory, err := datastoreBasicAuthFactory(false, "/missing/credential.json")
	if err != nil || factory != nil {
		t.Fatalf("disabled backend factory = %v, err = %v; want nil, nil", factory, err)
	}
	client, err := datastoreBasicAuthClient(false, "", nil)
	if err != nil || client != nil {
		t.Fatalf("disabled backend client = %v, err = %v; want nil, nil", client, err)
	}

	credential := filepath.Join(t.TempDir(), "credential.json")
	if err := os.WriteFile(credential, []byte(`{"username":"store","password":"test-only"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	factory, err = datastoreBasicAuthFactory(true, credential)
	if err != nil || factory == nil {
		t.Fatalf("enabled backend factory = %v, err = %v", factory, err)
	}
	if _, err := datastoreBasicAuthClient(true, "", factory); err == nil || !strings.Contains(err.Error(), "without a datastore endpoint") {
		t.Fatalf("enabled backend without endpoint error = %v", err)
	}
	client, err = datastoreBasicAuthClient(true, "https://store.example:8443", factory)
	if err != nil || client == nil {
		t.Fatalf("enabled backend client = %v, err = %v", client, err)
	}
}

// CODE-001: buildServeStores carries the store-construction phase that used to
// inline ~140 lines into run(), and returns ONE aggregate closer in place of the
// long defer chain. This test asserts (a) the all-memory profile builds, (b) the
// returned closer tears everything down without panicking, and (c) the bundle is
// fully populated — the closer-on-success path of the leak guarantee.
func TestBuildServeStoresBuildsAndClosesCleanly(t *testing.T) {
	cfg, err := config.Load(func(k string) string {
		// All planes in memory mode → no external infra, deterministic in CI.
		return map[string]string{
			"PROBECTL_DATABASE_URL":       "postgres://probectl:test-only@localhost:5432/probectl?sslmode=require",
			"PROBECTL_BUS_MODE":           "memory",
			"PROBECTL_TSDB_MODE":          "memory",
			"PROBECTL_PATHSTORE_MODE":     "memory",
			"PROBECTL_OTELSTORE_MODE":     "memory",
			"PROBECTL_FLOWSTORE_MODE":     "memory",
			"PROBECTL_EBPFSTORE_MODE":     "memory",
			"PROBECTL_ENDPOINTSTORE_MODE": "memory",
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
	if st.endpointStore == nil {
		t.Error("endpointStore is nil")
	}

	// The aggregate closer must run all teardowns without panicking, and be
	// idempotent enough to call once (it's invoked via defer in run()).
	closeStores()
}

func TestBuildServeStoresWiresTenantObjectStore(t *testing.T) {
	objectDir := t.TempDir()
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"PROBECTL_DATABASE_URL":       "postgres://probectl:test-only@localhost:5432/probectl?sslmode=require",
			"PROBECTL_BUS_MODE":           "memory",
			"PROBECTL_TSDB_MODE":          "memory",
			"PROBECTL_PATHSTORE_MODE":     "memory",
			"PROBECTL_OTELSTORE_MODE":     "memory",
			"PROBECTL_FLOWSTORE_MODE":     "memory",
			"PROBECTL_EBPFSTORE_MODE":     "memory",
			"PROBECTL_ENDPOINTSTORE_MODE": "memory",
			"PROBECTL_OBJECTSTORE_DIR":    objectDir,
		}[k]
	})
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	log := logging.New(io.Discard, "error", "json")

	st, closeStores, err := buildServeStores(cfg, log)
	if err != nil {
		t.Fatalf("buildServeStores with object store: %v", err)
	}
	defer closeStores()
	if st.objectStore == nil {
		t.Fatal("PROBECTL_OBJECTSTORE_DIR must wire a tenant object store")
	}
	if err := st.objectStore.Put(context.Background(), "tenant/tnA/browser/proof.png", "image/png", []byte("png")); err != nil {
		t.Fatalf("object store put: %v", err)
	}
	if _, exists, err := st.objectStore.Stat(context.Background(), "tenant/tnA/browser/proof.png"); err != nil || !exists {
		t.Fatalf("object store stat: exists=%v err=%v", exists, err)
	}
}

func TestBuildServeStoresSharesAuthenticatedPrometheusQueryUpstream(t *testing.T) {
	var observedUser, observedPassword string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedUser, observedPassword, _ = r.BasicAuth()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
	}))
	defer upstream.Close()
	credential := filepath.Join(t.TempDir(), "prometheus.json")
	if err := os.WriteFile(credential, []byte(`{"username":"store","password":"test-only"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(func(k string) string {
		return map[string]string{
			"PROBECTL_DATABASE_URL":               "postgres://probectl:test-only@localhost:5432/probectl?sslmode=require",
			"PROBECTL_BUS_MODE":                   "memory",
			"PROBECTL_TSDB_MODE":                  "prometheus",
			"PROBECTL_TSDB_URL":                   upstream.URL,
			"PROBECTL_TSDB_BASIC_AUTH_FILE":       credential,
			"PROBECTL_PATHSTORE_MODE":             "memory",
			"PROBECTL_OTELSTORE_MODE":             "memory",
			"PROBECTL_FLOWSTORE_MODE":             "memory",
			"PROBECTL_EBPFSTORE_MODE":             "memory",
			"PROBECTL_ENDPOINTSTORE_MODE":         "memory",
			"PROBECTL_REMOTE_WRITE_BATCH_ENABLED": "false",
		}[k]
	})
	if err != nil {
		t.Fatalf("config load: %v", err)
	}
	st, closeStores, err := buildServeStores(cfg, logging.New(io.Discard, "error", "json"))
	if err != nil {
		t.Fatalf("buildServeStores: %v", err)
	}
	defer closeStores()
	if st.promUpstream == nil {
		t.Fatal("authenticated Prometheus mode must construct the release query upstream")
	}
	selector, err := promapi.ParseSelector(`probectl_test_metric{tenant_id="tenant-a"}`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := st.promUpstream.QueryInstant(context.Background(), selector, time.Now())
	if err != nil || result.Status != http.StatusOK {
		t.Fatalf("authenticated query result = %+v, err = %v", result, err)
	}
	if observedUser != "store" || observedPassword != "test-only" {
		t.Fatalf("query upstream Basic auth = %q/%q, want configured credential", observedUser, observedPassword)
	}
}
