// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package pathstore

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestClickHouseHTTPStore exercises the ClickHouse HTTP adapter against a fake
// endpoint: connect runs the versioned migrations (ledger DDL → schema DDL →
// ledger record, U-046) and Save POSTs tenant-tagged JSONEachRow inserts.
func TestClickHouseHTTPStore(t *testing.T) {
	var mu sync.Mutex
	var queries, bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		queries = append(queries, r.URL.Query().Get("query"))
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ch, err := NewClickHouse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	find := func(substr string) int {
		mu.Lock()
		defer mu.Unlock()
		for i, q := range queries {
			if strings.Contains(q, substr) {
				return i
			}
		}
		return -1
	}
	ledger := find("CREATE TABLE IF NOT EXISTS probectl_ch_migrations")
	hops := find("CREATE TABLE IF NOT EXISTS probectl_path_hops")
	links := find("CREATE TABLE IF NOT EXISTS probectl_path_links")
	record := find("INSERT INTO probectl_ch_migrations")
	if ledger == -1 || hops == -1 || links == -1 || record == -1 {
		t.Fatalf("connect must run ledger DDL, schema DDL and the ledger record, got %v", queries)
	}
	if ledger >= hops || hops >= links || links >= record {
		t.Fatalf("migration order wrong (ledger=%d hops=%d links=%d record=%d)", ledger, hops, links, record)
	}

	if err := ch.Save(context.Background(), "tenant-x", samplePath()); err != nil {
		t.Fatal(err)
	}
	hi := find("INSERT INTO probectl_path_hops")
	li := find("INSERT INTO probectl_path_links")
	if hi == -1 || li == -1 || hi > li {
		t.Fatalf("save must insert hops then links, got %v", queries)
	}
	if !strings.Contains(queries[hi], "JSONEachRow") {
		t.Errorf("hops insert query = %q", queries[hi])
	}
	if !strings.Contains(bodies[hi], "tenant-x") || !strings.Contains(bodies[hi], "10.0.0.1") || !strings.Contains(bodies[hi], "16001") {
		t.Errorf("hops body missing rows: %q", bodies[hi])
	}
	if !strings.Contains(bodies[li], `"from_ip":"10.0.0.1"`) || !strings.Contains(bodies[li], `"to_ip":"8.8.8.8"`) {
		t.Errorf("links body = %q", bodies[li])
	}
}

func TestClickHousePropagatesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Code: 60. Table does not exist", http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewClickHouse(srv.URL); err == nil {
		t.Error("a 500 from ClickHouse should surface as an error")
	}
}
