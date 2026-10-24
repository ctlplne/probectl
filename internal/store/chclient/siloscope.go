// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// DPR-323: the per-tenant-database half of storage-layer tenant isolation for
// ClickHouse reads (docs/guardrails.md G7-1).
//
// A siloed or hybrid tenant's telemetry lives in its own ClickHouse database,
// optionally on a residency data plane. Until DPR-323 its reads ran as the
// control login, which no row policy filters, so the database name the silo
// router produced was the whole boundary: a routing bug that named tenant Y's
// database for tenant X's read, together with a read that lost its WHERE,
// served Y's rows to X.
//
// Those reads now run as the reader login (RouteRead). The reader holds
// SELECT on a per-tenant table only after that table carries the same
// setting-scoped row policy as the pooled tables, so ClickHouse returns only
// rows whose tenant_id is the request's tenant: a misrouted read finds
// nothing. SiloScope installs that state for one per-tenant database, proves
// it, and removes it at teardown.

// SiloReaderPolicy is the row-policy name on every per-tenant table.
const SiloReaderPolicy = "probectl_reader_scope"

// siloIdentRe is the shape a per-tenant database or table name must have to
// appear unquoted in DDL. Identifiers cannot be bound parameters; anything
// else is refused rather than quoted (fail closed).
var siloIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,190}$`)

// siloUserRe is the shape of a ClickHouse user named unquoted in DDL.
var siloUserRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// ErrSiloScopeUnbound refuses a per-tenant reader scope whose reader lane or
// login is not configured: the reader would hold no grant there, so a
// tenant's reads of its own database could only fail.
var ErrSiloScopeUnbound = errors.New("chclient: per-tenant database reader scope refused: tenant scoping is on but the reader lane or reader login is not bound (DPR-323)")

// SiloTable is one table of a per-tenant database, as the catalog reports it.
type SiloTable struct {
	Name   string
	Engine string
	// TenantColumn reports whether the table has a tenant_id column.
	TenantColumn bool
}

// holdsRows reports whether a table stores rows itself. A view holds none: a
// materialized view writes TO a table that is listed in its own right. The
// reader is granted no view.
func (t SiloTable) holdsRows() bool { return !strings.HasSuffix(t.Engine, "View") }

// siloDataTables validates a per-tenant database's catalog and returns the
// tables that hold rows. A table that holds rows but has no tenant_id cannot
// be filtered by the policy, so it is refused, never granted.
func siloDataTables(database string, tables []SiloTable) ([]SiloTable, error) {
	if !siloIdentRe.MatchString(database) {
		return nil, fmt.Errorf("chclient: refusing malformed per-tenant database name %q", database)
	}
	var out []SiloTable
	for _, t := range tables {
		if !t.holdsRows() {
			continue
		}
		if !siloIdentRe.MatchString(t.Name) {
			return nil, fmt.Errorf("chclient: per-tenant database %s holds a table %q the reader scope cannot name; refusing to grant the reader any of it", database, t.Name)
		}
		if !t.TenantColumn {
			return nil, fmt.Errorf("chclient: per-tenant table %s.%s has no tenant_id column, so the reader row policy cannot filter it; refusing to grant the reader any of it", database, t.Name)
		}
		out = append(out, t)
	}
	return out, nil
}

// SiloReaderScopeStatements returns, in order, the statements that put a
// per-tenant database's tables under the reader row policy and only then let
// the reader read them. Each table's policy precedes its grant, and a policy
// is converged in place (create if absent, then ALTER; never OR REPLACE,
// which removes it first: DPR-325), so once a table is granted its policy is
// never absent. A run that stops part way leaves a table ungranted (the reader
// is refused), never granted and unfiltered. Grants are per table, never
// database-wide, so a table created later is unreadable by the reader until it
// is scoped too.
func SiloReaderScopeStatements(database string, tables []SiloTable, tenantSetting, readerUser string) ([]string, error) {
	if !siloUserRe.MatchString(readerUser) {
		return nil, fmt.Errorf("chclient: refusing malformed ClickHouse reader user %q", readerUser)
	}
	if !siloIdentRe.MatchString(tenantSetting) {
		return nil, fmt.Errorf("chclient: refusing malformed tenant setting name %q", tenantSetting)
	}
	data, err := siloDataTables(database, tables)
	if err != nil {
		return nil, err
	}
	stmts := make([]string, 0, 2*len(data))
	for _, t := range data {
		qualified := database + "." + t.Name
		stmts = append(stmts, ReaderRowPolicyStatements(SiloReaderPolicy, qualified, tenantSetting, readerUser)...)
		stmts = append(stmts, "GRANT SELECT ON "+qualified+" TO "+readerUser)
	}
	return stmts, nil
}

// SiloReaderRevokeStatements undoes SiloReaderScopeStatements: the grants go
// first, then the policies, the reverse of the order they were installed in.
func SiloReaderRevokeStatements(database string, tables []SiloTable, readerUser string) ([]string, error) {
	if !siloUserRe.MatchString(readerUser) {
		return nil, fmt.Errorf("chclient: refusing malformed ClickHouse reader user %q", readerUser)
	}
	data, err := siloDataTables(database, tables)
	if err != nil {
		return nil, err
	}
	stmts := []string{"REVOKE SELECT ON " + database + ".* FROM " + readerUser}
	for _, t := range data {
		stmts = append(stmts, "DROP ROW POLICY IF EXISTS "+SiloReaderPolicy+" ON "+database+"."+t.Name)
	}
	return stmts, nil
}

// SiloScope is one store's reader scope for per-tenant databases: the control
// login installs and removes it, and the reader login is what it binds.
type SiloScope struct {
	Plane string // log/error label, e.g. "flowstore"
	// Control is the store's control connection; ControlBase is its pooled
	// endpoint (a routed residency plane uses that plane's own URL).
	Control     *Conn
	ControlBase string
	// Reader is the store's reader lane, ReaderUser the login the policies
	// bind (the one EnsureReaderRowPolicy bound on the pooled tables).
	Reader        *Reader
	ReaderUser    string
	TenantSetting string
}

// Endpoint is the ClickHouse server a per-tenant database at routedBase lives
// on ("" = this store's pooled endpoint), without URL credentials. Stores that
// share a server share it, so a caller scopes each database once per server.
func (s SiloScope) Endpoint(routedBase string) string {
	if strings.TrimSpace(routedBase) != "" {
		return StripUserinfo(routedBase)
	}
	return StripUserinfo(s.ControlBase)
}

func (s SiloScope) controlLane(routedBase string) ReadLane {
	base := s.ControlBase
	if strings.TrimSpace(routedBase) != "" {
		base = routedBase
	}
	return ReadLane{Conn: s.Control, Base: strings.TrimRight(base, "/"), Key: routedBase}
}

func (s SiloScope) bound() error {
	if s.Control == nil || s.Reader == nil || strings.TrimSpace(s.ReaderUser) == "" {
		return fmt.Errorf("%s: %w", s.Plane, ErrSiloScopeUnbound)
	}
	return nil
}

// Ensure installs the reader scope on every table of database (idempotent:
// each policy is created if absent and altered in place, and a repeated GRANT
// is a no-op). It runs as the
// control login, which needs SELECT WITH GRANT OPTION to grant the reader.
func (s SiloScope) Ensure(ctx context.Context, routedBase, database string) error {
	if err := s.bound(); err != nil {
		return err
	}
	ctl := s.controlLane(routedBase)
	tables, err := siloCatalog(ctx, ctl, database)
	if err != nil {
		return fmt.Errorf("%s: per-tenant database %s: %w", s.Plane, database, err)
	}
	stmts, err := SiloReaderScopeStatements(database, tables, s.TenantSetting, s.ReaderUser)
	if err != nil {
		return fmt.Errorf("%s: %w", s.Plane, err)
	}
	return s.run(ctx, ctl, database, stmts)
}

// Revoke removes the reader scope from database (idempotent). A database that
// is already gone still has its grants revoked.
func (s SiloScope) Revoke(ctx context.Context, routedBase, database string) error {
	if s.Control == nil || strings.TrimSpace(s.ReaderUser) == "" {
		return fmt.Errorf("%s: %w", s.Plane, ErrSiloScopeUnbound)
	}
	ctl := s.controlLane(routedBase)
	tables, err := siloCatalog(ctx, ctl, database)
	if err != nil {
		return fmt.Errorf("%s: per-tenant database %s: %w", s.Plane, database, err)
	}
	stmts, err := SiloReaderRevokeStatements(database, tables, s.ReaderUser)
	if err != nil {
		return fmt.Errorf("%s: %w", s.Plane, err)
	}
	return s.run(ctx, ctl, database, stmts)
}

func (s SiloScope) run(ctx context.Context, ctl ReadLane, database string, stmts []string) error {
	for _, stmt := range stmts {
		status, code, body, err := selfCheckDo(ctx, ctl, http.MethodPost, stmt, "")
		if err != nil {
			return fmt.Errorf("%s: per-tenant database %s reader scope: %w", s.Plane, database, err)
		}
		if status/100 != 2 {
			hint := ""
			if code == accessDeniedCode && (strings.HasPrefix(stmt, "GRANT") || strings.HasPrefix(stmt, "REVOKE")) {
				hint = "; the control login needs SELECT ON *.* WITH GRANT OPTION to grant the reader its per-tenant tables (docs/isolation.md, DPR-323)"
			}
			return fmt.Errorf("%s: per-tenant database %s reader scope: %q: status %d: %s%s", s.Plane, database, firstWords(stmt), status, snippet(body), hint)
		}
	}
	return nil
}

// Verify proves, against the live server the database lives on, what a
// tenant's read of it relies on, and fails otherwise:
//
//  1. the reader lane for that server authenticates as ReaderUser and is not
//     the control login;
//  2. the reader can neither INSERT into nor CREATE in the database;
//  3. on every table that holds any row, the reader under a tenant that owns
//     none of them sees zero rows: the tenant's own setting is the only key
//     that opens its database, so a read misrouted there finds nothing. (An
//     empty table has nothing to leak yet; the check re-runs at every boot.)
func (s SiloScope) Verify(ctx context.Context, routedBase, database string) error {
	if err := s.bound(); err != nil {
		return err
	}
	ctl := s.controlLane(routedBase)
	rdr, err := RouteRead(true, readerSelfCheckTenant, true, routedBase, s.Control, s.Reader)
	if err != nil {
		return fmt.Errorf("%s: %w", s.Plane, err)
	}
	check := ReaderCheck{Plane: s.Plane + " per-tenant database " + database, ReaderUser: s.ReaderUser, TenantSetting: s.TenantSetting}
	if _, _, err := verifyReaderLogin(ctx, ctl, rdr, check); err != nil {
		return err
	}
	tables, err := siloCatalog(ctx, ctl, database)
	if err != nil {
		return fmt.Errorf("%s: %w", check.Plane, err)
	}
	data, err := siloDataTables(database, tables)
	if err != nil {
		return fmt.Errorf("%s: %w", check.Plane, err)
	}
	if len(data) == 0 {
		return nil
	}
	for _, t := range data {
		check.Tables = append(check.Tables, database+"."+t.Name)
	}
	if err := verifyReaderCannotWrite(ctx, rdr, check); err != nil {
		return err
	}
	return verifyReaderSeesNoForeignRows(ctx, ctl, rdr, check)
}

// siloCatalog lists database's tables with their engines and whether each has
// a tenant_id column, read as the control login.
func siloCatalog(ctx context.Context, ctl ReadLane, database string) ([]SiloTable, error) {
	if !siloIdentRe.MatchString(database) {
		return nil, fmt.Errorf("chclient: refusing malformed per-tenant database name %q", database)
	}
	param := "&param_db=" + url.QueryEscape(database)
	tableRows, err := selfCheckQuery(ctx, ctl, "SELECT name, engine FROM system.tables WHERE database = {db:String} ORDER BY name FORMAT JSONEachRow", param)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	columnRows, err := selfCheckQuery(ctx, ctl, "SELECT table FROM system.columns WHERE database = {db:String} AND name = 'tenant_id' FORMAT JSONEachRow", param)
	if err != nil {
		return nil, fmt.Errorf("list tenant_id columns: %w", err)
	}
	hasTenant := map[string]bool{}
	for _, r := range columnRows {
		hasTenant[String(r["table"])] = true
	}
	out := make([]SiloTable, 0, len(tableRows))
	for _, r := range tableRows {
		name := String(r["name"])
		out = append(out, SiloTable{Name: name, Engine: String(r["engine"]), TenantColumn: hasTenant[name]})
	}
	return out, nil
}

// firstWords labels a statement in an error without its full text.
func firstWords(stmt string) string {
	fields := strings.Fields(stmt)
	if len(fields) > 6 {
		fields = fields[:6]
	}
	return strings.Join(fields, " ")
}
