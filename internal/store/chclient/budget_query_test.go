// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/breaker"
)

func TestBudgetedQueryRefusalsDoNotTripSharedTransport(t *testing.T) {
	for _, code := range []string{"158", "159", "160", "191", "241", "307", "396"} {
		t.Run(code, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/healthy" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("X-ClickHouse-Exception-Code", code)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(upstream.Close)
			conn := NewWithClient(upstream.Client())
			for range 8 {
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, nil)
				response, err := conn.DoBudgetedQuery("", req)
				if err != nil {
					t.Fatal("normal budget refusal poisoned the shared transport", err)
				}
				response.Body.Close()
				if response.StatusCode != http.StatusInternalServerError {
					t.Fatal("cost refusal was turned into success")
				}
			}
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL+"/healthy", nil)
			response, err := conn.DoBudgetedQuery("", req)
			if err != nil || response.StatusCode != http.StatusOK {
				t.Fatal("healthy sibling request was refused", err)
			}
			response.Body.Close()
			if conn.Stats().Trips != 0 {
				t.Fatal("query cost refusals tripped the infrastructure breaker")
			}
		})
	}
}

func TestBudgetedQueryPreservesInfrastructureAndDefaultBreakerFaults(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		codes  []string
		legacy bool
	}{
		{"unknown-server", 500, []string{"999"}, false},
		{"missing-code", 500, nil, false},
		{"ambiguous-code", 500, []string{"307", "307"}, false},
		{"service-unavailable", 503, []string{"307"}, false},
		{"rate-overload", 429, []string{"307"}, false},
		{"query-overload", 500, []string{"202"}, false},
		{"ordinary-Do-unchanged", 500, []string{"307"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, code := range test.codes {
					w.Header().Add("X-ClickHouse-Exception-Code", code)
				}
				w.WriteHeader(test.status)
			}))
			t.Cleanup(upstream.Close)
			conn := NewWithClient(upstream.Client())
			issue := conn.DoBudgetedQuery
			if test.legacy {
				issue = conn.Do
			}
			for range 5 {
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, nil)
				response, err := issue("", req)
				if response != nil {
					response.Body.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, nil)
			response, err := issue("", req)
			if response != nil {
				response.Body.Close()
			}
			if !errors.Is(err, breaker.ErrOpen) || response != nil || conn.Stats().Trips != 1 {
				t.Fatal("infrastructure/default breaker protection changed", err)
			}
		})
	}
}
