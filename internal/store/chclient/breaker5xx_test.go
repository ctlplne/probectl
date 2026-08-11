// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package chclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/breaker"
	"github.com/ctlplne/probectl/internal/crypto"
)

// TestDo_5xxTripsBreaker is the RESIL-005 acceptance test: an up-but-erroring
// ClickHouse endpoint that returns 503 repeatedly must trip the circuit breaker
// (a completed 5xx is a fault, not a success), while the response still
// surfaces so the caller can read the body/status.
func TestDo_5xxTripsBreaker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("overloaded"))
	}))
	defer srv.Close()

	c := NewWithClient(crypto.HardenedHTTPClient(time.Second))
	// default breaker threshold is 5 consecutive failures.
	const threshold = 5
	for i := 0; i < threshold; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
		resp, err := c.Do("", req)
		if err != nil {
			t.Fatalf("call %d: transport err = %v (the 5xx must surface as a real response, not an error)", i, err)
		}
		if resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("call %d: want surfaced 503 response, got %v", i, resp)
		}
		resp.Body.Close()
	}
	if st := c.Stats(); st.State != breaker.StateOpen {
		t.Fatalf("after %d consecutive 503s breaker state = %s, want open", threshold, st.State)
	}
}

// TestDo_429TripsBreaker: a 429 (Too Many Requests / overload) is also a fault.
func TestDo_429TripsBreaker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewWithClient(crypto.HardenedHTTPClient(time.Second))
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
		resp, err := c.Do("", req)
		if err != nil {
			t.Fatalf("call %d: err = %v", i, err)
		}
		resp.Body.Close()
	}
	if st := c.Stats(); st.State != breaker.StateOpen {
		t.Fatalf("after 429 storm breaker state = %s, want open", st.State)
	}
}

// TestDo_2xxDoesNotTrip: a healthy endpoint never trips the breaker.
func TestDo_2xxDoesNotTrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewWithClient(crypto.HardenedHTTPClient(time.Second))
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
		resp, err := c.Do("", req)
		if err != nil {
			t.Fatalf("call %d: err = %v", i, err)
		}
		resp.Body.Close()
	}
	if st := c.Stats(); st.State == breaker.StateOpen {
		t.Fatalf("healthy 200s tripped the breaker (state=%s)", st.State)
	}
}
