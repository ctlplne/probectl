// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpfstore

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
	c, err := NewClickHouseWithClient(srv.URL, 0, chtest.Client("control"))
	if err != nil {
		t.Fatal(err)
	}
	srv.Reset()
	return c, srv
}

// DPR-285: with tenant scoping on, every tenant read the store serves runs as
// the reader login with the tenant setting; erasure verification runs as the
// control login.
func TestEBPFTenantReadsRunAsTheReaderLogin(t *testing.T) {
	c, srv := newReaderLaneStore(t)
	c.WithTenantScoping(true).WithReader(chtest.Client("reader"))
	ctx := context.Background()
	if _, err := c.TopEdges(ctx, "tenant-a", EdgeQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExportTenant(ctx, "tenant-a", io.Discard); err != nil {
		t.Fatal(err)
	}
	chtest.AssertAll(t, srv.Requests("FROM "+edgesTable), "ebpf tenant read", "reader", "tenant-a")

	srv.Reset()
	// The fake answers the verification count with no row, which the store
	// reports as an unverifiable delete; only the login each request used
	// matters here.
	_, _ = c.DeleteTenant(ctx, "tenant-a")
	chtest.AssertAll(t, srv.Requests("SELECT count()"), "ebpf erasure count", "control", "")
	chtest.AssertAll(t, srv.Requests("DELETE WHERE"), "ebpf erasure", "control", "")
}

// DPR-285: scoping on without a reader fails closed; it never falls back to
// the control login.
func TestEBPFTenantReadWithoutReaderFailsClosed(t *testing.T) {
	c, srv := newReaderLaneStore(t)
	c.WithTenantScoping(true)
	ctx := context.Background()
	if _, err := c.TopEdges(ctx, "tenant-a", EdgeQuery{}); !errors.Is(err, chclient.ErrReaderRequired) {
		t.Fatalf("TopEdges err = %v, want ErrReaderRequired", err)
	}
	if _, err := c.ExportTenant(ctx, "tenant-a", io.Discard); !errors.Is(err, chclient.ErrReaderRequired) {
		t.Fatalf("export err = %v, want ErrReaderRequired", err)
	}
	if reqs := srv.Requests("SELECT"); len(reqs) != 0 {
		t.Fatalf("a refused read still reached ClickHouse: %+v", reqs)
	}
}

// DPR-323: a routed per-tenant database is read as the reader login too, with
// the tenant setting, so the per-tenant row policy filters it (a read misrouted
// to another tenant's database finds nothing). It never runs as control.
func TestEBPFSiloedTenantReadsRunAsTheReaderLogin(t *testing.T) {
	c, srv := newReaderLaneStore(t)
	c.WithTenantScoping(true).WithReader(chtest.Client("reader"))
	c.WithRouter(func(context.Context, string) (Target, error) { return Target{Database: "t_silo"}, nil })
	if _, err := c.TopEdges(context.Background(), "tenant-s", EdgeQuery{}); err != nil {
		t.Fatal(err)
	}
	chtest.AssertAll(t, srv.Requests("FROM t_silo."), "siloed ebpf read", "reader", "tenant-s")
}
