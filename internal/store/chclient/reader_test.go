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
	"strings"
	"testing"
)

func TestRouteReadPicksTheReaderForPooledTenantReads(t *testing.T) {
	control := NewWithClient(http.DefaultClient)
	reader := NewReader(http.DefaultClient, "http://probectl:pw@127.0.0.1:8123/")
	const pooledBase = "http://127.0.0.1:8123"
	for _, tc := range []struct {
		name       string
		scoping    bool
		tenant     string
		siloed     bool
		routed     string
		reader     *Reader
		wantReader bool
		wantBase   string // the reader lane's endpoint
		wantErr    error
	}{
		{name: "scoping off reads as control", tenant: "a", reader: reader},
		{name: "scoping off siloed reads as control", tenant: "a", siloed: true, routed: "https://ch-eu:8443", reader: reader},
		{name: "pooled scoped read rides the reader", scoping: true, tenant: "a", reader: reader, wantReader: true, wantBase: pooledBase},
		{name: "pooled scoped read without a reader fails closed", scoping: true, tenant: "a", wantErr: ErrReaderRequired},
		{name: "scoped read without a tenant fails closed", scoping: true, reader: reader, wantErr: ErrReaderTenantRequired},
		// DPR-323: a per-tenant database is read as the reader too, never as
		// the control login, so ClickHouse filters it by the tenant setting.
		{name: "siloed database on the default plane rides the reader", scoping: true, tenant: "a", siloed: true, reader: reader, wantReader: true, wantBase: pooledBase},
		{name: "siloed database on a residency plane rides the reader there", scoping: true, tenant: "a", siloed: true, routed: "https://ch-eu:8443/", reader: reader, wantReader: true, wantBase: "https://ch-eu:8443"},
		{name: "siloed database without a reader fails closed", scoping: true, tenant: "a", siloed: true, routed: "https://ch-eu:8443", wantErr: ErrReaderRequired},
		{name: "siloed database without a tenant fails closed", scoping: true, siloed: true, reader: reader, wantErr: ErrReaderTenantRequired},
		{name: "routed plane without a database fails closed", scoping: true, tenant: "a", routed: "https://ch-eu:8443", reader: reader, wantErr: ErrReaderRoutedPooled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lane, err := RouteRead(tc.scoping, tc.tenant, tc.siloed, tc.routed, control, tc.reader)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if lane.Reader != tc.wantReader {
				t.Fatalf("reader lane = %v, want %v", lane.Reader, tc.wantReader)
			}
			if tc.wantReader && (lane.Conn != reader.conn || lane.Base != tc.wantBase || lane.Key != tc.routed) {
				t.Fatalf("reader lane = %+v: want reader conn, base %q (no userinfo) and breaker key %q", lane, tc.wantBase, tc.routed)
			}
			if !tc.wantReader && (lane.Conn != control || lane.Key != tc.routed) {
				t.Fatalf("control lane = %+v", lane)
			}
		})
	}
}

func TestNewReaderNeverBuildsAnUnauthenticatedLane(t *testing.T) {
	if r := NewReader(nil, "http://127.0.0.1:8123"); r != nil {
		t.Fatal("a nil client must give no reader, not an unauthenticated default-user client")
	}
}

// fakeServer answers the self-check queries for two logins.
type fakeServer struct {
	readerName      string // what currentUser() says for the reader login
	readerDB        string
	readerCanWrite  bool
	readerSeesRows  bool
	controlHasRows  bool
	readerWasScoped bool
}

func (f *fakeServer) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		q := r.URL.Query().Get("query")
		reader := user == "reader"
		switch {
		case strings.HasPrefix(q, "SELECT currentUser()"):
			name, db := "control", "default"
			if reader {
				name, db = f.readerName, f.readerDB
			}
			_, _ = w.Write([]byte(`{"u":"` + name + `","db":"` + db + `"}` + "\n"))
		case strings.HasPrefix(q, "INSERT"), strings.HasPrefix(q, "CREATE TABLE"):
			if !reader {
				t.Fatalf("write probe sent as %q", user)
			}
			if !f.readerCanWrite {
				w.Header().Set("X-ClickHouse-Exception-Code", "497")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("Code: 497. DB::Exception: Not enough privileges. (ACCESS_DENIED)"))
			}
		case strings.HasPrefix(q, "SELECT count()"):
			n := "0"
			if reader {
				f.readerWasScoped = r.URL.Query().Get("SQL_probectl_tenant") == readerSelfCheckTenant
				if f.readerSeesRows {
					n = "1"
				}
			} else if f.controlHasRows {
				n = "1"
			}
			_, _ = w.Write([]byte(`{"n":"` + n + `"}` + "\n"))
		default:
			t.Fatalf("unexpected self-check query %q", q)
		}
	}
}

func authClient(user string) *http.Client {
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.SetBasicAuth(user, "self-check-password-ci-only")
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifyReader(t *testing.T) {
	check := ReaderCheck{Plane: "pathstore", ReaderUser: "probectl_reader", TenantSetting: "SQL_probectl_tenant", Tables: []string{"probectl_path_hops2"}}
	good := func() *fakeServer {
		return &fakeServer{readerName: "probectl_reader", readerDB: "default", controlHasRows: true}
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*fakeServer)
		noRdr   bool
		user    string // overrides check.ReaderUser
		wantErr string
	}{
		{name: "a policy-bound least-privilege reader passes"},
		{name: "no reader lane refuses", noRdr: true, wantErr: "no reader connection"},
		{name: "a credential for another user refuses", mutate: func(f *fakeServer) { f.readerName = "someone_else" }, wantErr: `authenticates as ClickHouse user "someone_else"`},
		{name: "a credential for the control login refuses", mutate: func(f *fakeServer) { f.readerName = "control" }, wantErr: `authenticates as ClickHouse user "control"`},
		{name: "a policy bound to the control login refuses", user: "control", mutate: func(f *fakeServer) { f.readerName = "control" }, wantErr: "is the control login"},
		{name: "a different default database refuses", mutate: func(f *fakeServer) { f.readerDB = "other" }, wantErr: "resolves database"},
		{name: "a write-capable reader refuses", mutate: func(f *fakeServer) { f.readerCanWrite = true }, wantErr: "not least-privilege"},
		{name: "a reader the policy does not bind refuses", mutate: func(f *fakeServer) { f.readerSeesRows = true }, wantErr: "does not bind it"},
		{name: "an empty table has nothing to leak yet", mutate: func(f *fakeServer) { f.controlHasRows = false; f.readerSeesRows = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := good()
			if tc.mutate != nil {
				tc.mutate(f)
			}
			srv := httptest.NewServer(f.handler(t))
			defer srv.Close()
			var reader *Reader
			if !tc.noRdr {
				reader = NewReader(authClient("reader"), srv.URL)
			}
			c := check
			if tc.user != "" {
				c.ReaderUser = tc.user
			}
			err := VerifyReader(context.Background(), NewWithClient(authClient("control")), srv.URL, reader, c)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyReader: %v", err)
				}
				if f.controlHasRows && !f.readerWasScoped {
					t.Fatal("the reader count did not carry the self-check tenant setting")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestStripUserinfo(t *testing.T) {
	for in, want := range map[string]string{
		"http://probectl:pw@localhost:8123/": "http://localhost:8123",
		"https://clickhouse:8443":            "https://clickhouse:8443",
		"https://clickhouse:8443/prefix/":    "https://clickhouse:8443/prefix",
	} {
		if got := StripUserinfo(in); got != want {
			t.Errorf("StripUserinfo(%q) = %q, want %q", in, got, want)
		}
	}
}
