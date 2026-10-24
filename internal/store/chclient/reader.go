// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package chclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DPR-285: storage-layer tenant isolation for ClickHouse reads
// (docs/guardrails.md G7-1).
//
// The setting-scoped row policy (ReaderRowPolicyStatements) binds ONE ClickHouse
// login: the reader. It filters nothing for any other login, and ClickHouse's
// default users_without_row_policies_can_read_rows=true lets every other login
// read every row. A store that sent its tenant reads as the control login (the
// one that owns the schema and writes) was therefore isolated only by its own
// WHERE tenant_id clause, while the policy guarded a login nobody used.
//
// Reader is the separate read lane a store sends every tenant-scoped read
// (pooled, and since DPR-323 per-tenant databases too) through when tenant
// scoping is on: its own connection, authenticated
// as the least-privilege reader login, carrying the per-request tenant setting.
// The DB then returns only that tenant's rows even if a query loses its WHERE.

// ErrReaderRequired is returned when tenant scoping is on and a tenant read
// has no reader lane. The read fails rather than falling back to the control
// login (fail closed).
var ErrReaderRequired = errors.New("chclient: tenant-scoped ClickHouse read refused: tenant scoping is on but no reader connection is attached (PROBECTL_CLICKHOUSE_READER_BASIC_AUTH_FILE); tenant reads never run as the control login (DPR-285)")

// ErrReaderTenantRequired refuses a tenant-scoped read that names no tenant.
var ErrReaderTenantRequired = errors.New("chclient: tenant-scoped ClickHouse read refused: no tenant to scope it to")

// ErrReaderRoutedPooled refuses a read of shared tables on a routed data plane.
// Every routed target the silo router produces carries its own per-tenant
// database, so a routed target without one is a routing contradiction, not a
// read to guess at.
var ErrReaderRoutedPooled = errors.New("chclient: tenant-scoped ClickHouse read refused: a routed data plane without a per-tenant database is a routing contradiction")

// Reader is the tenant-read lane of one ClickHouse-backed store.
type Reader struct {
	conn *Conn
	base string
}

// NewReader builds the reader lane over client, which must authenticate as
// the reader login (production: an origin-pinned basic-auth client from
// internal/crypto). storeBase is the store's pooled endpoint; URL userinfo is
// removed so the control login's URL credential can never ride a reader
// request. A nil client returns nil: NewWithClient's nil fallback is an
// unauthenticated client, which ClickHouse would serve as its default user.
func NewReader(client *http.Client, storeBase string) *Reader {
	if client == nil {
		return nil
	}
	return &Reader{conn: NewWithClient(client), base: StripUserinfo(storeBase)}
}

// StripUserinfo returns raw without URL credentials or a trailing slash.
func StripUserinfo(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User == nil {
		return strings.TrimRight(raw, "/")
	}
	u.User = nil
	return strings.TrimRight(u.String(), "/")
}

// ReadLane is where one read is sent.
type ReadLane struct {
	Conn *Conn
	// Base is the endpoint the request URL is built against ("" means the
	// caller's own routed-or-default endpoint).
	Base string
	// Key is the breaker key handed to Conn.Do.
	Key string
	// Reader reports whether the read runs as the reader login.
	Reader bool
}

// RouteRead picks the lane for one tenant read (DPR-285, DPR-323):
//
//   - scoping off: the control connection. That is the single-tenant profile,
//     where app-layer WHERE scoping is the documented boundary.
//   - scoping on: the reader lane, or ErrReaderRequired when none is attached.
//     Never the control login. A pooled read goes to the store's own
//     endpoint. A routed per-tenant database (siloed/hybrid) is read as the
//     same reader login, on the tenant's residency plane when it has one
//     (the reader's credential for that plane is pinned to its origin,
//     PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES). The per-tenant tables
//     carry the same setting-scoped row policy as the pooled ones (SiloScope),
//     so a read the router sent to another tenant's database finds no row.
func RouteRead(scoping bool, tenant string, siloed bool, routedBase string, control *Conn, reader *Reader) (ReadLane, error) {
	if !scoping {
		return ReadLane{Conn: control, Key: routedBase}, nil
	}
	if strings.TrimSpace(tenant) == "" {
		return ReadLane{}, ErrReaderTenantRequired
	}
	routed := strings.TrimSpace(routedBase) != ""
	if routed && !siloed {
		return ReadLane{}, ErrReaderRoutedPooled
	}
	if reader == nil {
		return ReadLane{}, ErrReaderRequired
	}
	lane := ReadLane{Conn: reader.conn, Base: reader.base, Reader: true}
	if routed {
		lane.Base, lane.Key = StripUserinfo(routedBase), routedBase
	}
	return lane, nil
}

// readerSelfCheckTenant is the tenant setting the boot check reads under. It
// is not a tenant id (tenant ids are UUIDs), so a correctly bound policy shows
// the reader no row at all.
const readerSelfCheckTenant = "probectl-reader-selfcheck"

// accessDeniedCode is ClickHouse's ACCESS_DENIED error code.
const accessDeniedCode = "497"

// ReaderCheck is the boot proof that a store's reader lane is DB-enforced.
type ReaderCheck struct {
	Plane         string // log/error label, e.g. "pathstore"
	ReaderUser    string // the login the row policy binds (PROBECTL_*_READER_USER)
	TenantSetting string // the custom setting the policy reads
	// Tables are the pooled tables the store installed the policy on.
	Tables []string
}

// VerifyReader proves, against the live server, what the reader lane relies
// on, and refuses to start otherwise:
//
//  1. the reader credential authenticates as ReaderUser, is not the control
//     login, and resolves the same default database as the control login;
//  2. the reader can neither INSERT nor CREATE (ACCESS_DENIED), so it is not a
//     write-capable login wearing a reader name;
//  3. on every table that holds any row, the reader under a tenant that owns
//     none sees zero rows, so the setting-scoped policy really binds it. (A
//     table with no rows yet has nothing to leak; the check re-runs at boot.)
func VerifyReader(ctx context.Context, control *Conn, controlBase string, reader *Reader, check ReaderCheck) error {
	if reader == nil {
		return fmt.Errorf("%s: %w", check.Plane, ErrReaderRequired)
	}
	if len(check.Tables) == 0 {
		return fmt.Errorf("%s: reader self-check has no tables to verify", check.Plane)
	}
	ctl := ReadLane{Conn: control, Base: strings.TrimRight(controlBase, "/")}
	rdr := ReadLane{Conn: reader.conn, Base: reader.base, Reader: true}
	if err := verifyReaderIdentity(ctx, ctl, rdr, check); err != nil {
		return err
	}
	if err := verifyReaderCannotWrite(ctx, rdr, check); err != nil {
		return err
	}
	return verifyReaderSeesNoForeignRows(ctx, ctl, rdr, check)
}

func verifyReaderIdentity(ctx context.Context, ctl, rdr ReadLane, check ReaderCheck) error {
	readerDB, controlDB, err := verifyReaderLogin(ctx, ctl, rdr, check)
	if err != nil {
		return err
	}
	if readerDB != controlDB {
		return fmt.Errorf("%s: the reader resolves database %q but the store's tables live in %q; give the reader that default database (DPR-285)", check.Plane, readerDB, controlDB)
	}
	return nil
}

// verifyReaderLogin proves the reader lane authenticates as check.ReaderUser
// and is not the control login. It returns both logins' default databases.
func verifyReaderLogin(ctx context.Context, ctl, rdr ReadLane, check ReaderCheck) (readerDB, controlDB string, err error) {
	const who = "SELECT currentUser() AS u, currentDatabase() AS db FORMAT JSONEachRow"
	readerRows, err := selfCheckQuery(ctx, rdr, who, "")
	if err != nil {
		return "", "", fmt.Errorf("%s: reader credential cannot query ClickHouse: %w", check.Plane, err)
	}
	controlRows, err := selfCheckQuery(ctx, ctl, who, "")
	if err != nil {
		return "", "", fmt.Errorf("%s: control login cannot query ClickHouse: %w", check.Plane, err)
	}
	if len(readerRows) == 0 || len(controlRows) == 0 {
		return "", "", fmt.Errorf("%s: reader self-check: empty identity result", check.Plane)
	}
	readerUser, controlUser := String(readerRows[0]["u"]), String(controlRows[0]["u"])
	switch {
	case readerUser != check.ReaderUser:
		return "", "", fmt.Errorf("%s: the reader credential authenticates as ClickHouse user %q, but the row policy binds %q (DPR-285)", check.Plane, readerUser, check.ReaderUser)
	case readerUser == controlUser:
		return "", "", fmt.Errorf("%s: the reader credential is the control login %q; tenant reads need a separate least-privilege reader (DPR-285)", check.Plane, controlUser)
	}
	return String(readerRows[0]["db"]), String(controlRows[0]["db"]), nil
}

func verifyReaderCannotWrite(ctx context.Context, rdr ReadLane, check ReaderCheck) error {
	table := check.Tables[0]
	for _, probe := range []struct{ what, sql string }{
		// An empty INSERT and a CREATE of an existing name: both are refused
		// on privileges before they could do anything, and neither changes
		// data when a login does hold the privilege.
		{"INSERT", "INSERT INTO " + table + " FORMAT JSONEachRow"},
		{"CREATE TABLE", "CREATE TABLE " + table + " (probectl_reader_selfcheck UInt8) ENGINE = Memory"},
	} {
		status, code, body, err := selfCheckDo(ctx, rdr, http.MethodPost, probe.sql, "")
		if err != nil {
			return fmt.Errorf("%s: reader %s probe: %w", check.Plane, probe.what, err)
		}
		if status/100 == 2 || code != accessDeniedCode {
			return fmt.Errorf("%s: the reader login %q is not least-privilege: %s on %s was not refused with ACCESS_DENIED (status %d, code %q: %s) (DPR-285)",
				check.Plane, check.ReaderUser, probe.what, table, status, code, snippet(body))
		}
	}
	return nil
}

func verifyReaderSeesNoForeignRows(ctx context.Context, ctl, rdr ReadLane, check ReaderCheck) error {
	for _, table := range check.Tables {
		probe := "SELECT count() AS n FROM (SELECT 1 FROM " + table + " LIMIT 1) FORMAT JSONEachRow"
		held, err := selfCheckQuery(ctx, ctl, probe, "")
		if err != nil {
			return fmt.Errorf("%s: reader self-check (control count of %s): %w", check.Plane, table, err)
		}
		if Count(held) == 0 {
			continue
		}
		seen, err := selfCheckQuery(ctx, rdr, probe, "&"+url.QueryEscape(check.TenantSetting)+"="+url.QueryEscape(readerSelfCheckTenant))
		if err != nil {
			return fmt.Errorf("%s: reader self-check (reader count of %s): %w", check.Plane, table, err)
		}
		if Count(seen) != 0 {
			return fmt.Errorf("%s: the reader login %q reads rows of %s that belong to no tenant it was scoped to: the setting-scoped row policy does not bind it, so ClickHouse would not enforce tenant isolation (DPR-285)",
				check.Plane, check.ReaderUser, table)
		}
	}
	return nil
}

func selfCheckQuery(ctx context.Context, lane ReadLane, sql, extra string) ([]map[string]any, error) {
	status, _, body, err := selfCheckDo(ctx, lane, http.MethodGet, sql, extra)
	if err != nil {
		return nil, err
	}
	if status/100 != 2 {
		return nil, fmt.Errorf("status %d: %s", status, snippet(body))
	}
	return Decode(body)
}

func selfCheckDo(ctx context.Context, lane ReadLane, method, sql, extra string) (status int, code string, body []byte, err error) {
	u := lane.Base + "/?query=" + url.QueryEscape(sql) + extra
	var reqBody io.Reader
	if method == http.MethodPost {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reqBody)
	if err != nil {
		return 0, "", nil, err
	}
	resp, err := lane.Conn.Do(lane.Key, req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	body, err = ReadResponseBody(resp.Body)
	if err != nil {
		return 0, "", nil, err
	}
	return resp.StatusCode, resp.Header.Get("X-ClickHouse-Exception-Code"), body, nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
