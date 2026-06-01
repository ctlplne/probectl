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
// endpoint: it must POST the schema DDL on connect and JSONEachRow inserts on
// Save, tenant-tagged.
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
	if len(queries) != 2 || !strings.Contains(queries[0], "CREATE TABLE") || !strings.Contains(queries[0], "netctl_path_hops") {
		t.Fatalf("schema DDL = %v", queries)
	}
	if !strings.Contains(queries[1], "netctl_path_links") {
		t.Errorf("links DDL missing: %v", queries[1])
	}

	if err := ch.Save(context.Background(), "tenant-x", samplePath()); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 4 {
		t.Fatalf("after save, %d queries, want 4: %v", len(queries), queries)
	}
	if !strings.Contains(queries[2], "INSERT INTO netctl_path_hops") || !strings.Contains(queries[2], "JSONEachRow") {
		t.Errorf("hops insert query = %q", queries[2])
	}
	if !strings.Contains(bodies[2], "tenant-x") || !strings.Contains(bodies[2], "10.0.0.1") || !strings.Contains(bodies[2], "16001") {
		t.Errorf("hops body missing rows: %q", bodies[2])
	}
	if !strings.Contains(queries[3], "INSERT INTO netctl_path_links") {
		t.Errorf("links insert query = %q", queries[3])
	}
	if !strings.Contains(bodies[3], `"from_ip":"10.0.0.1"`) || !strings.Contains(bodies[3], `"to_ip":"8.8.8.8"`) {
		t.Errorf("links body = %q", bodies[3])
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
