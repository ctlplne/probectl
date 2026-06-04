//go:build integration

package pathstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestClickHouseRealRoundTrip writes a path to a real ClickHouse over HTTP and
// reads back the hop rows. Set PROBECTL_PATHSTORE_URL (e.g. http://localhost:8123);
// the test skips when it is unset.
func TestClickHouseRealRoundTrip(t *testing.T) {
	base := os.Getenv("PROBECTL_PATHSTORE_URL")
	if base == "" {
		t.Skip("set PROBECTL_PATHSTORE_URL to run the ClickHouse round-trip test")
	}
	ch, err := NewClickHouse(base)
	if err != nil {
		t.Fatalf("connect/schema: %v", err)
	}
	tenant := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	if err := ch.Save(context.Background(), tenant, samplePath()); err != nil {
		t.Fatalf("save: %v", err)
	}

	q := fmt.Sprintf("SELECT count() FROM probectl_path_hops WHERE tenant_id = '%s'", tenant)
	u := strings.TrimRight(base, "/") + "/?query=" + url.QueryEscape(q)
	resp, err := http.Get(u) //nolint:gosec // localhost test query
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "2" {
		t.Errorf("hop row count = %q, want 2", strings.TrimSpace(string(body)))
	}
}
