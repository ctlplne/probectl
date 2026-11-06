// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func roleQueryFixture(tenant string, at time.Time) []InterfaceRoleProjection {
	scope := entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}
	a := InterfaceRoleProjection{Scope: scope, RouterID: "33333333-3333-4333-8333-333333333333", InterfaceID: "44444444-4444-4444-8444-444444444444",
		Exporter: "192.0.2.1", Protocol: "ipfix", Domain: 4294967295, IfIndex: 7, Role: entity.InterfaceRoleTransit, Reason: "provider_asn",
		Sources: []string{"policy/1/9", "evidence/2"}, ValidUntil: at.Add(time.Minute)}
	b := a
	b.InterfaceID, b.IfIndex, b.Role = "55555555-5555-4555-8555-555555555555", 8, entity.InterfaceRoleCustomer
	return []InterfaceRoleProjection{a, b}
}

func TestInterfaceRoleQueryProjectionKeepsTenantIdentityAndCompleteMetadata(t *testing.T) {
	const a, b = "11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"
	at := time.Now().UTC().Truncate(time.Microsecond)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(a))
	rows := roleQueryFixture(a, at)
	lookup, err := NewInterfaceRoleQueryData(ctx, a, at, rows, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := lookup.Digest(ctx, a, at)
	if err != nil || len(digest) != 64 {
		t.Fatal("complete role provenance was not bound", digest, err)
	}
	reordered := slices.Clone(rows)
	slices.Reverse(reordered)
	other, err := NewInterfaceRoleQueryData(ctx, a, at.Add(time.Second), reordered, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := other.Digest(ctx, a, at.Add(time.Second)); err != nil || got != digest {
		t.Fatal("role identity depends on input order or computation clock", got, err)
	}
	row := Row{TenantID: a, AgentID: "forged-other-context", Exporter: "::ffff:192.0.2.1", Protocol: "ipfix", ObsDomain: 4294967295, InIf: 7, OutIf: 8}
	if lookup.valueForRow(row, false) != string(entity.InterfaceRoleTransit) || lookup.valueForRow(row, true) != string(entity.InterfaceRoleCustomer) {
		t.Fatal("role lookup lost direction, full domain or canonical exporter")
	}
	for _, change := range []func(*Row){
		func(r *Row) { r.Exporter = "192.0.2.2" }, func(r *Row) { r.ObsDomain = 0 },
		func(r *Row) { r.Protocol = "sflow5" }, func(r *Row) { r.InIf = 0 }, func(r *Row) { r.TenantID = b },
	} {
		unknown := row
		change(&unknown)
		if lookup.valueForRow(unknown, false) != string(entity.InterfaceRoleOther) {
			t.Fatal("unbound flow claimed another role", unknown)
		}
	}
	if _, err := lookup.Digest(tenancy.WithTenant(t.Context(), tenancy.ID(b)), b, at); !errors.Is(err, ErrInterfaceRoleQueryScope) {
		t.Fatal("foreign tenant reused role publication identity", err)
	}
	if _, err := lookup.Digest(ctx, a, rows[0].ValidUntil); !errors.Is(err, ErrInterfaceRoleQueryScope) {
		t.Fatal("expired source retained query role authority", err)
	}
	rows[0].Sources[0], rows[0].Role = "changed caller metadata", entity.InterfaceRoleOther
	if got, err := lookup.Digest(ctx, a, at); err != nil || got != digest || lookup.rows[0].Sources[1] != "policy/1/9" || lookup.valueForRow(row, false) != string(entity.InterfaceRoleTransit) {
		t.Fatal("caller mutated role projection after admission", got, err)
	}
	changed := roleQueryFixture(a, at)
	changed[0].Sources[0] = "policy/1/10"
	later, err := NewInterfaceRoleQueryData(ctx, a, at, changed, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := later.Digest(ctx, a, at); err != nil || got == digest {
		t.Fatal("changed policy retained old role identity", got, err)
	}
}

func TestInterfaceRoleQueryProjectionRefusesAmbiguousExpiredOrPartialInputs(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	at := time.Now().UTC()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	for name, change := range map[string]func([]InterfaceRoleProjection) []InterfaceRoleProjection{
		"foreign": func(r []InterfaceRoleProjection) []InterfaceRoleProjection {
			r[1].TenantID = "66666666-6666-4666-8666-666666666666"
			return r
		},
		"expired":   func(r []InterfaceRoleProjection) []InterfaceRoleProjection { r[1].ValidUntil = at; return r },
		"duplicate": func(r []InterfaceRoleProjection) []InterfaceRoleProjection { return append(r, r[0]) },
		"other context": func(r []InterfaceRoleProjection) []InterfaceRoleProjection {
			r[1].ContextID = "77777777-7777-4777-8777-777777777777"
			r[1].Protocol = "sflow5"
			return r
		},
		"other router": func(r []InterfaceRoleProjection) []InterfaceRoleProjection {
			r[1].RouterID = "77777777-7777-4777-8777-777777777777"
			r[1].Domain = 0
			return r
		},
		"no provenance": func(r []InterfaceRoleProjection) []InterfaceRoleProjection { r[1].Sources = nil; return r },
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := NewInterfaceRoleQueryData(ctx, tenant, at, change(roleQueryFixture(tenant, at)), 1<<20); !errors.Is(err, ErrInterfaceRoleQueryScope) || out != nil {
				t.Fatal("ambiguous, foreign or stale role projection was partially admitted", out, err)
			}
		})
	}
	if out, err := NewInterfaceRoleQueryData(ctx, tenant, at, roleQueryFixture(tenant, at), 4096); !errors.Is(err, ErrExplorerBudget) || out != nil {
		t.Fatal("role projection escaped complete admission", out, err)
	}
	if out, err := NewInterfaceRoleQueryData(t.Context(), tenant, at, nil, 1<<20); !errors.Is(err, ErrInterfaceRoleQueryScope) || out != nil {
		t.Fatal("unscoped empty role projection was accepted", out, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if out, err := NewInterfaceRoleQueryData(canceled, tenant, at, nil, 1<<20); !errors.Is(err, context.Canceled) || out != nil {
		t.Fatal("cancelled role projection was accepted", out, err)
	}
}
