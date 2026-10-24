// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pathstore

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

func newReaderLaneStore(t *testing.T) (*ClickHouse, *chtest.Server) {
	t.Helper()
	srv := chtest.New(t)
	c, err := NewClickHouseRetainedWithClient(srv.URL, 0, chtest.Client("control"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Reset()
	return c, srv
}

// DPR-285: with tenant scoping on, every tenant read the store serves runs as
// the reader login with the tenant setting; erasure verification runs as the
// control login.
func TestPathTenantReadsRunAsTheReaderLogin(t *testing.T) {
	c, srv := newReaderLaneStore(t)
	c.WithTenantScoping(true).WithReader(chtest.Client("reader"))
	ctx := context.Background()
	if _, _, err := c.Latest(ctx, "tenant-a", "x.example"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.History(ctx, "tenant-a", "x.example", HistoryQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExportTenantHops(ctx, "tenant-a", io.Discard); err != nil {
		t.Fatal(err)
	}
	chtest.AssertAll(t, srv.Requests("FROM "+hopsTable), "path tenant read", "reader", "tenant-a")

	srv.Reset()
	if _, _, err := c.DeleteTenant(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	chtest.AssertAll(t, srv.Requests("SELECT count()"), "path erasure count", "control", "")
	chtest.AssertAll(t, srv.Requests("DELETE FROM"), "path erasure", "control", "")
}

// DPR-285: scoping on without a reader fails closed; it never falls back to
// the control login.
func TestPathTenantReadWithoutReaderFailsClosed(t *testing.T) {
	c, srv := newReaderLaneStore(t)
	c.WithTenantScoping(true)
	ctx := context.Background()
	if _, _, err := c.Latest(ctx, "tenant-a", "x.example"); !errors.Is(err, chclient.ErrReaderRequired) {
		t.Fatalf("Latest err = %v, want ErrReaderRequired", err)
	}
	if _, err := c.ExportTenantLinks(ctx, "tenant-a", io.Discard); !errors.Is(err, chclient.ErrReaderRequired) {
		t.Fatalf("export err = %v, want ErrReaderRequired", err)
	}
	if reqs := srv.Requests("SELECT"); len(reqs) != 0 {
		t.Fatalf("a refused read still reached ClickHouse: %+v", reqs)
	}
}

// DPR-323: a routed per-tenant database is read as the reader login too, with
// the tenant setting, so the per-tenant row policy filters it (a read misrouted
// to another tenant's database finds nothing). It never runs as control.
func TestPathSiloedTenantReadsRunAsTheReaderLogin(t *testing.T) {
	c, srv := newReaderLaneStore(t)
	c.WithTenantScoping(true).WithReader(chtest.Client("reader"))
	c.WithRouter(func(context.Context, string) (Target, error) { return Target{Database: "t_silo"}, nil })
	if _, _, err := c.Latest(context.Background(), "tenant-s", "x.example"); err != nil {
		t.Fatal(err)
	}
	chtest.AssertAll(t, srv.Requests("FROM t_silo."), "siloed path read", "reader", "tenant-s")
}
