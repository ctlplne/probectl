// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package chtest holds the ClickHouse test helpers for the reader-lane
// isolation work (DPR-285): a recording stand-in for the ClickHouse HTTP
// interface, for contract tests of WHICH login a store sends each request as,
// and the provisioning of a real least-privilege reader login on a live
// server for the isolation suites. The stand-in answers every request 200
// with an empty result, so a store's migrations and reads run without a
// server; it keeps the authenticated user, the SQL and the per-request tenant
// setting of each one. It is a test harness: nothing in it is linked into a
// product binary.
package chtest

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TenantSetting is the custom setting the reader row policy filters on.
const TenantSetting = "SQL_probectl_tenant"

// Request is one recorded ClickHouse request.
type Request struct {
	User   string // the basic-auth user it authenticated as
	Query  string
	Tenant string // the SQL_probectl_tenant value it carried ("" = none)
}

// Server records every request it answers.
type Server struct {
	*httptest.Server
	mu       sync.Mutex
	requests []Request
}

// New starts a recording server, closed with the test.
func New(t *testing.T) *Server {
	t.Helper()
	s := &Server{}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	user, _, _ := r.BasicAuth()
	q := r.URL.Query()
	query := q.Get("query")
	s.mu.Lock()
	s.requests = append(s.requests, Request{User: user, Query: query, Tenant: q.Get(TenantSetting)})
	s.mu.Unlock()
	if strings.Contains(query, "FORMAT JSON") && !strings.Contains(query, "FORMAT JSONEachRow") {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}
}

// Reset forgets every request recorded so far (e.g. the store's migrations).
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = nil
}

// Requests returns the recorded requests whose SQL contains match.
func (s *Server) Requests(match string) []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Request
	for _, r := range s.requests {
		if strings.Contains(r.Query, match) {
			out = append(out, r)
		}
	}
	return out
}

// Client returns an HTTP client that authenticates every request as user.
func Client(user string) *http.Client {
	c := crypto.HardenedHTTPClient(30 * time.Second)
	c.Transport = basicAuth{user: user, base: c.Transport}
	return c
}

type basicAuth struct {
	user string
	base http.RoundTripper
}

func (b basicAuth) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.SetBasicAuth(b.user, "chtest-password-ci-only")
	return b.base.RoundTrip(clone)
}

// AssertAll fails the test unless at least one request matched and every one
// was sent as user carrying tenant (tenant "" asserts no setting is required).
func AssertAll(t *testing.T, reqs []Request, what, user, tenant string) {
	t.Helper()
	if len(reqs) == 0 {
		t.Fatalf("%s: no request recorded", what)
	}
	for _, r := range reqs {
		if r.User != user {
			t.Fatalf("%s ran as %q, want %q: %s", what, r.User, user, r.Query)
		}
		if tenant != "" && r.Tenant != tenant {
			t.Fatalf("%s carried tenant setting %q, want %q: %s", what, r.Tenant, tenant, r.Query)
		}
	}
}
