// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestClickHouseRealRoundTrip writes a path to a real ClickHouse over HTTP and
// reads back the hop rows. Set PROBECTL_PATHSTORE_URL (e.g. http://localhost:8123);
// the test skips when it is unset.
func TestClickHouseRealRoundTrip(t *testing.T) {
	base := os.Getenv("PROBECTL_PATHSTORE_URL")
	if base == "" {
		testsupport.SkipOrFatal(t, "set PROBECTL_PATHSTORE_URL to run the ClickHouse round-trip test")
	}
	ch, err := newClickHouse(base)
	if err != nil {
		t.Fatalf("connect/schema: %v", err)
	}
	tenant := fmt.Sprintf("itest-%d", time.Now().UnixNano())
	if err := ch.Save(context.Background(), tenant, samplePath()); err != nil {
		t.Fatalf("save: %v", err)
	}

	q := fmt.Sprintf("SELECT count() FROM %s WHERE tenant_id = '%s'", hopsTable, tenant)
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
