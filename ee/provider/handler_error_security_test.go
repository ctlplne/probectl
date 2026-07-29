// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProviderInternalErrorsAreRedacted(t *testing.T) {
	const sentinel = "postgres connection failed for secret-db.internal"
	var logs bytes.Buffer
	h := &Handler{log: slog.New(slog.NewTextHandler(&logs, nil))}

	rec := httptest.NewRecorder()
	h.writeErr(rec, errors.New(sentinel))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Error.Code != "internal" || body.Error.Message != "internal error" {
		t.Fatalf("error envelope = %+v", body.Error)
	}
	if strings.Contains(rec.Body.String(), sentinel) {
		t.Fatalf("internal detail crossed the HTTP boundary: %s", rec.Body.String())
	}
	if !strings.Contains(logs.String(), sentinel) {
		t.Fatalf("server log omitted the original error: %s", logs.String())
	}

	rec = httptest.NewRecorder()
	h.writeErr(rec, errBadDecision)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("4xx status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 4xx response: %v", err)
	}
	if body.Error.Code != "bad_request" || body.Error.Message != errBadDecision.Error() {
		t.Fatalf("4xx domain detail changed: %+v", body.Error)
	}
}
