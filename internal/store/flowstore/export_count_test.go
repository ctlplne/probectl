// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// DPR-287: the export manifest's flow count is the number of rows the export
// stream carried, not a count() taken afterwards. Under live ingest the two
// disagree, and the tenant-export receipt caught a manifest claiming 90 flows
// for an 85-line flows.jsonl.
func TestExportTenantCountsTheStreamedRows(t *testing.T) {
	const streamed = "{\"tenant_id\":\"tenant-a\"}\n{\"tenant_id\":\"tenant-a\"}\n{\"tenant_id\":\"tenant-a\"}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := r.URL.Query().Get("query") + string(body)
		switch {
		case strings.Contains(q, "SELECT count()"):
			// Rows that arrived after the stream: a later count disagrees.
			_, _ = io.WriteString(w, "{\"n\":\"99\"}\n")
		case strings.Contains(q, "SELECT *"):
			_, _ = io.WriteString(w, streamed)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := NewClickHouseWithClient(srv.URL, 0, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	n, err := c.ExportTenant(context.Background(), "tenant-a", &out)
	if err != nil {
		t.Fatal(err)
	}
	if lines := int64(strings.Count(out.String(), "\n")); n != lines || n != 3 {
		t.Fatalf("ExportTenant reported %d rows for a %d-line export, want 3", n, lines)
	}
}
