// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

// compCH records which per-tenant databases exist, and can be told to fail one
// named plane's Ensure — the fault injection this finding requires.
type compCH struct {
	created  map[string]bool
	failOn   string
	dropFail string
}

func newCompCH() *compCH { return &compCH{created: map[string]bool{}} }

func (f *compCH) ensure(plane, db string) error {
	if f.failOn == plane {
		return fmt.Errorf("injected %s provisioning failure", plane)
	}
	f.created[plane+":"+db] = true
	return nil
}

func (f *compCH) drop(plane, db string) error {
	if f.dropFail == plane {
		return fmt.Errorf("injected %s teardown failure", plane)
	}
	delete(f.created, plane+":"+db)
	return nil
}

func (f *compCH) live() []string {
	var out []string
	for k := range f.created {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type compFlow struct{ *compCH }
type compPath struct{ *compCH }
type compEBPF struct{ *compCH }
type compOtel struct{ *compCH }
type compEndpoint struct{ *compCH }

func (f compFlow) EnsureTenantDatabase(_ context.Context, t flowstore.Target, _ int) error {
	return f.ensure("flow", t.Database)
}
func (f compFlow) DropTenantDatabase(_ context.Context, t flowstore.Target) error {
	return f.drop("flow", t.Database)
}
func (f compPath) EnsureTenantDatabase(_ context.Context, t pathstore.Target, _ int) error {
	return f.ensure("path", t.Database)
}
func (f compPath) DropTenantDatabase(_ context.Context, t pathstore.Target) error {
	return f.drop("path", t.Database)
}
func (f compEBPF) EnsureTenantDatabase(_ context.Context, t ebpfstore.Target, _ int) error {
	return f.ensure("ebpf", t.Database)
}
func (f compEBPF) DropTenantDatabase(_ context.Context, t ebpfstore.Target) error {
	return f.drop("ebpf", t.Database)
}
func (f compOtel) EnsureTenantDatabase(_ context.Context, t otelstore.Target, _ int) error {
	return f.ensure("otel", t.Database)
}
func (f compOtel) DropTenantDatabase(_ context.Context, t otelstore.Target) error {
	return f.drop("otel", t.Database)
}
func (f compEndpoint) EnsureTenantDatabase(_ context.Context, t endpointstore.Target, _ int) error {
	return f.ensure("endpoint", t.Database)
}
func (f compEndpoint) DropTenantDatabase(_ context.Context, t endpointstore.Target) error {
	return f.drop("endpoint", t.Database)
}

func provisionerWithFakes(ch *compCH) *Provisioner {
	return NewProvisioner(nil, CHPlanes{
		Flows:    compFlow{ch},
		Paths:    compPath{ch},
		EBPF:     compEBPF{ch},
		Otel:     compOtel{ch},
		Endpoint: compEndpoint{ch},
	}, nil, 30, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// TestProvisionCompensatesEveryLegFailure is S-fadcec95's proof: fail each
// ClickHouse leg in turn and require that NO per-tenant database survives.
// Before this, provisionCH early-returned with no compensation, so a failure
// at leg N left legs 1..N-1's databases orphaned behind an abandoned
// provisioning row.
func TestProvisionCompensatesEveryLegFailure(t *testing.T) {
	for _, plane := range []string{"flow", "path", "ebpf", "otel", "endpoint"} {
		ch := newCompCH()
		ch.failOn = plane
		p := provisionerWithFakes(ch)

		err := p.provisionCH(context.Background(), "tenant-a", "")
		if err == nil {
			t.Fatalf("%s: provisioning must fail when its leg fails", plane)
		}
		if !strings.Contains(err.Error(), plane) {
			t.Fatalf("%s: error must name the failing plane: %v", plane, err)
		}
		if live := ch.live(); len(live) != 0 {
			t.Fatalf("%s leg failed but these databases survived: %v — compensation did not run", plane, live)
		}
	}
}

// TestProvisionSucceedsLeavesEveryPlane: the happy path is unchanged — all
// five databases exist. Without this the compensation test could pass by
// never creating anything.
func TestProvisionSucceedsLeavesEveryPlane(t *testing.T) {
	ch := newCompCH()
	p := provisionerWithFakes(ch)
	if err := p.provisionCH(context.Background(), "tenant-a", ""); err != nil {
		t.Fatal(err)
	}
	if got := len(ch.live()); got != 5 {
		t.Fatalf("successful provisioning left %d databases, want 5: %v", got, ch.live())
	}
}

// TestProvisionReportsUncompensatableOrphans: when the UNDO itself fails, the
// error must say so — an un-droppable database is exactly the orphan an
// operator has to be told about, never swallowed.
func TestProvisionReportsUncompensatableOrphans(t *testing.T) {
	ch := newCompCH()
	ch.failOn = "ebpf"   // third leg fails...
	ch.dropFail = "flow" // ...and undoing the first leg also fails
	p := provisionerWithFakes(ch)

	err := p.provisionCH(context.Background(), "tenant-a", "")
	if err == nil {
		t.Fatal("provisioning must fail")
	}
	if !strings.Contains(err.Error(), "compensate flow plane") {
		t.Fatalf("a failed compensation must be reported, got: %v", err)
	}
	if !strings.Contains(err.Error(), "provision ebpf plane") {
		t.Fatalf("the original failure must be preserved alongside it, got: %v", err)
	}
	// The path leg (leg 2) compensated fine; only flow's database remains.
	if live := ch.live(); len(live) != 1 || !strings.HasPrefix(live[0], "flow:") {
		t.Fatalf("only the un-droppable flow database should remain, got %v", live)
	}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) {
		t.Fatal("the provision and compensation errors must both be recoverable from the result")
	}
}
