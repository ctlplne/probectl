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
	"sync"
	"testing"
)

const siloDB = "probectl_t_0123abcd"

func siloCatalogFixture() []SiloTable {
	return []SiloTable{
		{Name: "probectl_flows", Engine: "ReplacingMergeTree", TenantColumn: true},
		{Name: "probectl_flow_rollups_hour", Engine: "ReplacingMergeTree", TenantColumn: true},
		{Name: "probectl_flow_rollups_hour_mv", Engine: "MaterializedView", TenantColumn: true},
	}
}

// DPR-323: every per-tenant table gets the setting-scoped policy BEFORE the
// reader is granted it, the grant is per table, and views are never granted.
func TestSiloReaderScopeStatementsPolicyPrecedesEachGrant(t *testing.T) {
	stmts, err := SiloReaderScopeStatements(siloDB, siloCatalogFixture(), "SQL_probectl_tenant", "probectl_reader")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"CREATE ROW POLICY IF NOT EXISTS probectl_reader_scope ON " + siloDB + ".probectl_flows FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO `probectl_reader`",
		"ALTER ROW POLICY probectl_reader_scope ON " + siloDB + ".probectl_flows FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO `probectl_reader`",
		"GRANT SELECT ON " + siloDB + ".probectl_flows TO `probectl_reader`",
		"CREATE ROW POLICY IF NOT EXISTS probectl_reader_scope ON " + siloDB + ".probectl_flow_rollups_hour FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO `probectl_reader`",
		"ALTER ROW POLICY probectl_reader_scope ON " + siloDB + ".probectl_flow_rollups_hour FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO `probectl_reader`",
		"GRANT SELECT ON " + siloDB + ".probectl_flow_rollups_hour TO `probectl_reader`",
	}
	if strings.Join(stmts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("scope statements:\n%s\nwant:\n%s", strings.Join(stmts, "\n"), strings.Join(want, "\n"))
	}
	for _, s := range stmts {
		if strings.Contains(s, ".*") || strings.Contains(s, "_mv") || strings.Contains(s, "OR REPLACE") {
			t.Fatalf("the reader must be granted per data table, never a database wildcard or a view: %s", s)
		}
	}
}

func TestSiloReaderScopeStatementsRefuseWhatThePolicyCannotFilter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		db     string
		tables []SiloTable
		user   string
		want   string
	}{
		{name: "a data table without tenant_id", db: siloDB, user: "probectl_reader",
			tables: []SiloTable{{Name: "probectl_flows", Engine: "MergeTree"}}, want: "no tenant_id column"},
		{name: "a table name that cannot be named unquoted", db: siloDB, user: "probectl_reader",
			tables: []SiloTable{{Name: ".inner_id.0f", Engine: "MergeTree", TenantColumn: true}}, want: "cannot name"},
		{name: "a malformed database", db: "probectl_t_x; DROP", user: "probectl_reader", want: "malformed per-tenant database"},
		{name: "a malformed reader user", db: siloDB, user: "reader TO ALL", want: "malformed ClickHouse reader user"},
		{name: "an empty reader user", db: siloDB, user: "", want: "malformed ClickHouse reader user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stmts, err := SiloReaderScopeStatements(tc.db, tc.tables, "SQL_probectl_tenant", tc.user)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v (statements %v), want it to contain %q", err, stmts, tc.want)
			}
		})
	}
}

func TestSiloReaderRevokeStatementsRevokeBeforeDroppingPolicies(t *testing.T) {
	stmts, err := SiloReaderRevokeStatements(siloDB, siloCatalogFixture(), "probectl_reader")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"REVOKE SELECT ON " + siloDB + ".* FROM `probectl_reader`",
		"DROP ROW POLICY IF EXISTS probectl_reader_scope ON " + siloDB + ".probectl_flows",
		"DROP ROW POLICY IF EXISTS probectl_reader_scope ON " + siloDB + ".probectl_flow_rollups_hour",
	}
	if strings.Join(stmts, "\n") != strings.Join(want, "\n") {
		t.Fatalf("revoke statements:\n%s\nwant:\n%s", strings.Join(stmts, "\n"), strings.Join(want, "\n"))
	}
}

// siloFake is one ClickHouse server holding one per-tenant database, serving
// the control and reader logins.
type siloFake struct {
	t               *testing.T
	readerName      string
	readerCanWrite  bool
	readerSeesRows  bool
	controlHasRows  bool
	denyGrant       bool
	grants          []string // nil = the documented pooled + per-table grants
	mu              sync.Mutex
	statements      []string
	readerTenantSet string
}

func (f *siloFake) handler(w http.ResponseWriter, r *http.Request) {
	user, _, _ := r.BasicAuth()
	reader := user == "reader"
	q := r.URL.Query().Get("query")
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasPrefix(q, "SELECT name, engine FROM system.tables"):
		if r.URL.Query().Get("param_db") != siloDB {
			f.t.Errorf("catalog read for database %q", r.URL.Query().Get("param_db"))
		}
		_, _ = w.Write([]byte(`{"name":"probectl_flows","engine":"ReplacingMergeTree"}` + "\n" + `{"name":"probectl_flow_rollups_hour_mv","engine":"MaterializedView"}` + "\n"))
	case strings.HasPrefix(q, "SELECT table FROM system.columns"):
		_, _ = w.Write([]byte(`{"table":"probectl_flows"}` + "\n" + `{"table":"probectl_flow_rollups_hour_mv"}` + "\n"))
	case strings.HasPrefix(q, "SHOW GRANTS"):
		grants := f.grants
		if grants == nil {
			grants = []string{"GRANT SELECT ON default.* TO probectl_reader", "GRANT SELECT ON " + siloDB + ".probectl_flows TO probectl_reader"}
		}
		_, _ = w.Write([]byte(strings.Join(grants, "\n") + "\n"))
	case strings.HasPrefix(q, "SELECT currentUser()"):
		name := "control"
		if reader {
			name = f.readerName
		}
		_, _ = w.Write([]byte(`{"u":"` + name + `","db":"default"}` + "\n"))
	case strings.HasPrefix(q, "INSERT"), strings.HasPrefix(q, "CREATE TABLE"):
		if !reader {
			f.t.Errorf("write probe sent as %q", user)
		}
		if !f.readerCanWrite {
			w.Header().Set("X-ClickHouse-Exception-Code", accessDeniedCode)
			w.WriteHeader(http.StatusForbidden)
		}
	case strings.HasPrefix(q, "SELECT count()"):
		if !strings.Contains(q, siloDB+".probectl_flows") {
			f.t.Errorf("count of an unexpected table: %s", q)
		}
		n := "0"
		if reader {
			f.readerTenantSet = r.URL.Query().Get("SQL_probectl_tenant")
			if f.readerSeesRows {
				n = "1"
			}
		} else if f.controlHasRows {
			n = "1"
		}
		_, _ = w.Write([]byte(`{"n":"` + n + `"}` + "\n"))
	case strings.HasPrefix(q, "CREATE ROW POLICY"), strings.HasPrefix(q, "ALTER ROW POLICY"), strings.HasPrefix(q, "GRANT"), strings.HasPrefix(q, "REVOKE"), strings.HasPrefix(q, "DROP ROW POLICY"):
		if reader {
			f.t.Errorf("scope DDL sent as the reader: %s", q)
		}
		if f.denyGrant && strings.HasPrefix(q, "GRANT") {
			w.Header().Set("X-ClickHouse-Exception-Code", accessDeniedCode)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("Code: 497. Not enough privileges ... WITH GRANT OPTION"))
			return
		}
		f.statements = append(f.statements, q)
	default:
		f.t.Errorf("unexpected query %q", q)
	}
}

func siloScopeFor(t *testing.T, pooled, routed *httptest.Server) (SiloScope, string) {
	t.Helper()
	routedBase := ""
	if routed != nil {
		routedBase = routed.URL
	}
	return SiloScope{
		Plane: "flowstore", Control: NewWithClient(authClient("control")), ControlBase: pooled.URL,
		Reader: NewReader(authClient("reader"), pooled.URL), ReaderUser: "probectl_reader", TenantSetting: "SQL_probectl_tenant",
	}, routedBase
}

func TestSiloScopeEnsureAndVerify(t *testing.T) {
	good := func(t *testing.T) *siloFake {
		return &siloFake{t: t, readerName: "probectl_reader", controlHasRows: true}
	}
	for _, tc := range []struct {
		name    string
		mutate  func(*siloFake)
		routed  bool
		wantErr string
	}{
		{name: "a policy-bound reader on the default plane passes"},
		{name: "a policy-bound reader on a residency plane passes there", routed: true},
		{name: "a reader the per-tenant policy does not bind refuses", mutate: func(f *siloFake) { f.readerSeesRows = true }, wantErr: "does not bind it"},
		{name: "a write-capable reader refuses", mutate: func(f *siloFake) { f.readerCanWrite = true }, wantErr: "not least-privilege"},
		{name: "a plane credential for another login refuses", mutate: func(f *siloFake) { f.readerName = "someone_else" }, wantErr: `authenticates as ClickHouse user "someone_else"`},
		{name: "a control login without grant option is named", mutate: func(f *siloFake) { f.denyGrant = true }, wantErr: "WITH GRANT OPTION"},
		{name: "a database-wide grant on the silo refuses (DPR-328)", mutate: func(f *siloFake) {
			f.grants = []string{"GRANT SELECT ON default.* TO probectl_reader", "GRANT SELECT ON " + siloDB + ".* TO probectl_reader"}
		}, wantErr: "database-wide grant"},
		{name: "a global grant refuses (DPR-328)", mutate: func(f *siloFake) { f.grants = []string{"GRANT SELECT ON *.* TO probectl_reader"} }, wantErr: "DPR-328"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := good(t)
			if tc.mutate != nil {
				tc.mutate(f)
			}
			// The pooled server holds nothing for this database: a scope or
			// proof sent there instead of the routed plane fails the test.
			var pooled, routed *httptest.Server
			target := httptest.NewServer(http.HandlerFunc(f.handler))
			defer target.Close()
			pooled = target
			if tc.routed {
				routed = target
				pooled = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("per-tenant database work sent to the pooled server: %s", r.URL.Query().Get("query"))
					w.WriteHeader(http.StatusInternalServerError)
				}))
				defer pooled.Close()
			}
			scope, routedBase := siloScopeFor(t, pooled, routed)
			if got, want := scope.Endpoint(routedBase), target.URL; got != want {
				t.Fatalf("Endpoint = %q, want %q", got, want)
			}
			err := scope.Ensure(context.Background(), routedBase, siloDB)
			if err == nil {
				err = scope.Verify(context.Background(), routedBase, siloDB)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				"CREATE ROW POLICY IF NOT EXISTS probectl_reader_scope ON " + siloDB + ".probectl_flows FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO `probectl_reader`",
				"ALTER ROW POLICY probectl_reader_scope ON " + siloDB + ".probectl_flows FOR SELECT USING tenant_id = getSetting('SQL_probectl_tenant') TO `probectl_reader`",
				"GRANT SELECT ON " + siloDB + ".probectl_flows TO `probectl_reader`",
			}
			if strings.Join(f.statements, "\n") != strings.Join(want, "\n") {
				t.Fatalf("scope DDL = %q, want %q", f.statements, want)
			}
			if f.readerTenantSet != readerSelfCheckTenant {
				t.Fatalf("the reader's proof count carried tenant setting %q, want the self-check tenant", f.readerTenantSet)
			}
		})
	}
}

func TestSiloScopeRefusesAnUnboundReader(t *testing.T) {
	for name, scope := range map[string]SiloScope{
		"no reader lane":  {Plane: "flowstore", Control: NewWithClient(nil), ReaderUser: "probectl_reader"},
		"no reader login": {Plane: "flowstore", Control: NewWithClient(nil), Reader: NewReader(http.DefaultClient, "http://127.0.0.1:1")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := scope.Ensure(context.Background(), "", siloDB); !errors.Is(err, ErrSiloScopeUnbound) {
				t.Fatalf("Ensure err = %v, want ErrSiloScopeUnbound", err)
			}
			if err := scope.Verify(context.Background(), "", siloDB); !errors.Is(err, ErrSiloScopeUnbound) {
				t.Fatalf("Verify err = %v, want ErrSiloScopeUnbound", err)
			}
		})
	}
}

func TestSiloScopeRevoke(t *testing.T) {
	f := &siloFake{t: t, readerName: "probectl_reader"}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	defer srv.Close()
	scope, _ := siloScopeFor(t, srv, nil)
	if err := scope.Revoke(context.Background(), "", siloDB); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"REVOKE SELECT ON " + siloDB + ".* FROM `probectl_reader`",
		"DROP ROW POLICY IF EXISTS probectl_reader_scope ON " + siloDB + ".probectl_flows",
	}
	if strings.Join(f.statements, "\n") != strings.Join(want, "\n") {
		t.Fatalf("revoke DDL = %q, want %q", f.statements, want)
	}
}

func TestSiloReaderKeywordAccountIsExact(t *testing.T) {
	tables := []SiloTable{{Name: "probectl_flows", Engine: "Memory", TenantColumn: true}}
	install, err := SiloReaderScopeStatements(siloDB, tables, "SQL_probectl_tenant", "ALL")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range install {
		if !strings.HasSuffix(stmt, "TO `ALL`") {
			t.Fatalf("must bind exact account: %s", stmt)
		}
	}
	revoke, err := SiloReaderRevokeStatements(siloDB, tables, "ALL")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(revoke[0], "FROM `ALL`") {
		t.Fatalf("must revoke exact account: %s", revoke[0])
	}
}
