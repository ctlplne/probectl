// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/breaker"
)

func TestCallerCancellationCannotPoisonSharedStoreTransport(t *testing.T) {
	for _, budgeted := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "budgeted-query"}[budgeted], func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }))
			defer upstream.Close()
			conn := NewWithClient(upstream.Client())
			issue := conn.Do
			if budgeted {
				issue = conn.DoBudgetedQuery
			}
			for range 5 {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, nil)
				response, err := issue("", req)
				if response != nil {
					response.Body.Close()
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatal("canceled request did not return cancellation", err)
				}
			}
			if stats := conn.Stats(); stats.State != breaker.StateClosed || stats.ConsecFailures != 0 || calls.Load() != 0 {
				t.Fatal("canceled requests poisoned a healthy sibling", stats, calls.Load())
			}
			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, upstream.URL, nil)
			response, err := issue("", req)
			if response != nil {
				defer response.Body.Close()
			}
			if err != nil || response == nil || response.StatusCode != 200 {
				t.Fatal("healthy sibling was blocked after caller cancellations", err)
			}
		})
	}
}

func TestInflightStoreCancellationPreservesPriorFailure(t *testing.T) {
	started, ended := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done(); close(ended) }))
	defer upstream.Close()
	conn := NewWithClient(upstream.Client())
	_ = conn.def.Do(func() error { return errors.New("prior failure") })
	before := conn.Stats()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
	done := make(chan error, 1)
	go func() {
		response, err := conn.Do("", req)
		if response != nil {
			response.Body.Close()
		}
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("owned TLS request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled transport did not stop")
	}
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not reach owned TLS service")
	}
	if conn.Stats() != before {
		t.Fatal("caller abort changed existing upstream health", conn.Stats())
	}
}

func TestStoreClientOwnTimeoutStillTripsInfrastructureBreaker(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer upstream.Close()
	client := upstream.Client()
	client.Timeout = 50 * time.Millisecond
	conn := NewWithClient(client)
	conn.def = breaker.New(1, time.Minute)
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL, nil)
	response, err := conn.Do("", req)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || conn.Stats().State != breaker.StateOpen {
		t.Fatal("client's own timeout was mistaken for caller cancellation", err, conn.Stats())
	}
}

func TestCallerDeadlinePreservesSharedStoreHealth(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("expired caller reached the store")
	}))
	defer upstream.Close()
	conn := NewWithClient(upstream.Client())
	_ = conn.def.Do(func() error { return errors.New("prior owned failure") })
	before := conn.Stats()
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	for _, issue := range []func(string, *http.Request) (*http.Response, error){conn.Do, conn.DoBudgetedQuery} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL, nil)
		response, err := issue("", req)
		if response != nil {
			response.Body.Close()
		}
		if !errors.Is(err, context.DeadlineExceeded) || response != nil || conn.Stats() != before {
			t.Fatal("caller deadline changed shared store health", err, conn.Stats())
		}
	}
}
