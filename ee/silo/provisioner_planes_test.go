// SPDX-License-Identifier: LicenseRef-probectl-TBD

package silo

import (
	"context"
	"log/slog"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// fake*DDL record which planes were provisioned/torn down + the target they got.
type fakeFlow struct{ ensured, dropped []flowstore.Target }
type fakePath struct{ ensured, dropped []pathstore.Target }
type fakeEBPF struct{ ensured, dropped []ebpfstore.Target }
type fakeOtel struct{ ensured, dropped []otelstore.Target }

func (f *fakeFlow) EnsureTenantDatabase(_ context.Context, t flowstore.Target, _ int) error {
	f.ensured = append(f.ensured, t)
	return nil
}
func (f *fakeFlow) DropTenantDatabase(_ context.Context, t flowstore.Target) error {
	f.dropped = append(f.dropped, t)
	return nil
}
func (f *fakePath) EnsureTenantDatabase(_ context.Context, t pathstore.Target, _ int) error {
	f.ensured = append(f.ensured, t)
	return nil
}
func (f *fakePath) DropTenantDatabase(_ context.Context, t pathstore.Target) error {
	f.dropped = append(f.dropped, t)
	return nil
}
func (f *fakeEBPF) EnsureTenantDatabase(_ context.Context, t ebpfstore.Target, _ int) error {
	f.ensured = append(f.ensured, t)
	return nil
}
func (f *fakeEBPF) DropTenantDatabase(_ context.Context, t ebpfstore.Target) error {
	f.dropped = append(f.dropped, t)
	return nil
}
func (f *fakeOtel) EnsureTenantDatabase(_ context.Context, t otelstore.Target, _ int) error {
	f.ensured = append(f.ensured, t)
	return nil
}
func (f *fakeOtel) DropTenantDatabase(_ context.Context, t otelstore.Target) error {
	f.dropped = append(f.dropped, t)
	return nil
}

// TENANT-001: provisioning a siloed/hybrid tenant must create a per-tenant
// ClickHouse database on EVERY telemetry plane (flow/path/eBPF/otel), not flow
// alone — and on the residency-pinned data plane. Pre-fix only flow was wired.
// We use the HYBRID model so no Postgres leg is needed (pool can be nil).
func TestProvisionDrivesEveryCHPlane(t *testing.T) {
	flow := &fakeFlow{}
	path := &fakePath{}
	ebpf := &fakeEBPF{}
	otel := &fakeOtel{}
	planes := map[string]DataPlane{"eu": {CHURL: "https://ch-eu.example:8443"}}
	p := NewProvisioner(nil, CHPlanes{Flows: flow, Paths: path, EBPF: ebpf, Otel: otel}, planes, 30,
		slog.New(slog.NewTextHandler(discard{}, nil)))

	const tenant = "11111111-1111-1111-1111-111111111111"
	if err := p.Provision(context.Background(), tenant, "eu", tenancy.IsolationHybrid); err != nil {
		t.Fatalf("provision: %v", err)
	}

	wantDB := CHDatabase(tenant)
	const wantURL = "https://ch-eu.example:8443"
	checks := []struct {
		name        string
		db, baseURL string
	}{
		{"flow", first(flow.ensured).Database, first(flow.ensured).BaseURL},
		{"path", first(path.ensured).Database, first(path.ensured).BaseURL},
		{"ebpf", first(ebpf.ensured).Database, first(ebpf.ensured).BaseURL},
		{"otel", first(otel.ensured).Database, first(otel.ensured).BaseURL},
	}
	for _, c := range checks {
		if c.db != wantDB {
			t.Errorf("%s plane provisioned database %q, want the per-tenant %q (not pooled)", c.name, c.db, wantDB)
		}
		if c.baseURL != wantURL {
			t.Errorf("%s plane provisioned on %q, want the residency-pinned %q (data residency)", c.name, c.baseURL, wantURL)
		}
	}

	// Teardown must drop every plane's database too.
	if err := p.Teardown(context.Background(), tenant, "eu", tenancy.IsolationHybrid); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	if len(flow.dropped) != 1 || len(path.dropped) != 1 || len(ebpf.dropped) != 1 || len(otel.dropped) != 1 {
		t.Fatalf("teardown must drop all four planes: flow=%d path=%d ebpf=%d otel=%d",
			len(flow.dropped), len(path.dropped), len(ebpf.dropped), len(otel.dropped))
	}
}

func first[T any](s []T) T {
	var z T
	if len(s) == 0 {
		return z
	}
	return s[0]
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
