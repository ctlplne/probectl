// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

// TestOTLPTokenListResponseUsesSnakeCaseContract pins RTP-25: the GET
// /v1/otlp-tokens list must emit the snake_case OpenAPI contract keys, never the
// Go struct field names (ID/TenantID/CreatedAt...), and must not leak tenant_id
// (the POST /v1/otlp-tokens DTO omits it). handleOTLPTokenList serializes
// []store.OTLPToken directly, so this reproduces the handler's exact response
// body — map[string]any{"items": tokens} through the real writeJSON — which keeps
// the assertion meaningful in plain `go test` (the DB fetch + routing need a live
// Postgres the unit suite does not have). Dropping the struct's json tags
// reddens this test on an assertion.
func TestOTLPTokenListResponseUsesSnakeCaseContract(t *testing.T) {
	used := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	revoked := time.Date(2026, 1, 3, 3, 4, 5, 0, time.UTC)
	tokens := []store.OTLPToken{{
		ID:         "11111111-1111-4111-8111-111111111111",
		TenantID:   "tenant-must-not-leak",
		Name:       "edge-collector",
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		LastUsedAt: &used,
		RevokedAt:  &revoked,
	}}

	rec := httptest.NewRecorder()
	// The exact body handleOTLPTokenList writes (otlptokensapi.go).
	writeJSON(rec, http.StatusOK, map[string]any{"items": tokens})

	var body struct {
		Items []map[string]json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(body.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(body.Items))
	}
	item := body.Items[0]

	for _, key := range []string{"id", "name", "created_at", "last_used_at", "revoked_at"} {
		if _, ok := item[key]; !ok {
			t.Errorf("response item is missing snake_case key %q (keys present: %v)", key, sortedItemKeys(item))
		}
	}
	// Go field names are a wire-contract regression; tenant_id must never ride
	// along, in neither its struct-field nor snake_case spelling.
	for _, leaked := range []string{"ID", "TenantID", "CreatedAt", "LastUsedAt", "RevokedAt", "tenant_id"} {
		if _, ok := item[leaked]; ok {
			t.Errorf("response item leaks key %q; GET /v1/otlp-tokens must use the snake_case OpenAPI contract and must not expose tenant_id (keys present: %v)", leaked, sortedItemKeys(item))
		}
	}
	if strings.Contains(rec.Body.String(), "tenant-must-not-leak") {
		t.Errorf("response body leaked the tenant id value: %s", rec.Body.String())
	}
}

func sortedItemKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
