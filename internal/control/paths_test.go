// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http"
	"testing"
	"time"
)

func TestPathHistoryQueryValidation(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet,
		"/v1/tests/test-a/path/history?from=2026-07-14T12%3A00%3A00Z&to=2026-07-14T13%3A00%3A00Z&limit=2&round_id=round-a&round_id=round_b", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsePathHistoryQuery(req)
	if err != nil {
		t.Fatalf("valid query: %v", err)
	}
	if got.Limit != 2 || len(got.IDs) != 2 || got.IDs[0] != "round-a" || got.IDs[1] != "round_b" {
		t.Fatalf("parsed query = %+v", got)
	}
	if !got.From.Equal(time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)) ||
		!got.To.Equal(time.Date(2026, 7, 14, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("parsed clock = %s..%s", got.From, got.To)
	}

	invalid := []string{
		"?from=not-a-time",
		"?from=2026-07-14T13%3A00%3A00Z&to=2026-07-14T12%3A00%3A00Z",
		"?limit=0",
		"?limit=101",
		"?round_id=one&round_id=two&round_id=three",
		"?round_id=../../foreign",
	}
	for _, query := range invalid {
		t.Run(query, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/v1/tests/test-a/path/history"+query, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parsePathHistoryQuery(req); err == nil {
				t.Fatal("malformed history selector should fail closed")
			}
		})
	}
}
