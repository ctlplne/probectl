// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Application-role TLS Postgres/FORCE-RLS and original decoder/writer/reader.
// Issued identities and original MRT are modeled, not live upstream.
func TestPublicContextLookupKeepsWholeAssignedCohortTenantAndPrefixAbsence(t *testing.T) {
	f := newRoleInputsFixture(t)
	_, profile := publicSnapshotFixture()
	refs := []string{"ris/mrt_table_dump_v2/alpha", "ris/mrt_table_dump_v2/beta"}
	write := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error { return tenancy.InTenant(ctx, f.pool, fn) }); err != nil {
			t.Fatal(err)
		}
	}
	assign := func(tenant, reference string) {
		write(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, reference, f.contextID)
			return err
		})
	}
	for lane, tenant := range f.tenants {
		for i, reference := range refs {
			assign(tenant, reference)
			input := BGPPublicSnapshotInput{CollectorAgentID: "role-listener", SenderSerial: f.serials[tenant+"role-listener"], SourceRef: reference, ObservationID: uuid.NewString()}
			f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&input.ObservedAt)
			})
			input.SourceRecord = publicMRTRecordForTest([]byte{0, 255}, false, true, uint32(input.ObservedAt.Unix()))
			write(tenant, func(ctx context.Context, sc tenancy.Scope) error {
				got, err := (BGPRouting{}).StagePublicMRTSourceInScope(ctx, sc, input, profile, true)
				if err == nil && got.Status != "staged" {
					t.Fatal("public context fixture could not stage its whole source", got)
				}
				return err
			})
			for n, afi := range []uint16{1, 2, 0} {
				message := BGPPublicSnapshotMessage{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: reference, SnapshotID: input.ObservationID, Sequence: int64(n + 1), ObservedAt: time.Now(), Complete: afi == 0}
				var record []byte
				if afi != 0 {
					record = publicMRTRIBRecordForTest(afi, uint32(64497+lane*10+i), 0, uint32(input.ObservedAt.Unix()), false)
					if i == 1 && afi == 1 {
						// The complete second source sees a more-specific prefix.
						record = append(bytes.Clone(record[:20]), append([]byte{0}, record[20:]...)...)
						record[16] = 25
						binary.BigEndian.PutUint32(record[8:12], uint32(len(record)-12))
					}
				}
				write(tenant, func(ctx context.Context, sc tenancy.Scope) error {
					got, err := (BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, message, record, profile, time.Hour)
					if err == nil && got.Status != "applied" {
						t.Fatal("public context fixture could not publish complete source", got)
					}
					return err
				})
			}
		}
	}
	read := func(tenant string, scope entity.Scope, address string, budget BGPRoutingBudget) (BGPPublicContextLookup, error) {
		var got BGPPublicContextLookup
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			got, err = (BGPRouting{}).LookupPublicContextInScope(ctx, sc, scope, netip.MustParseAddr(address), budget, time.Hour)
			return err
		})
		return got, err
	}
	assertOwned := func(tenant string, lane int) {
		t.Helper()
		scope := entity.Scope{TenantID: tenant, ContextID: f.contextID}
		got, err := read(tenant, scope, "192.0.2.9", profile)
		if err != nil || got.Scope != scope || len(got.Sources) != 2 || len(got.Paths) != 2 || got.Prefix.String() != "192.0.2.0/25" || !got.ValidUntil.After(got.AsOf) {
			t.Fatal("public context omitted a source or changed complete longest-prefix evidence", got, err)
		}
		for i, source := range got.Sources {
			if source.Source.Scope != scope || source.Source.SourceRef != refs[i] || source.SnapshotID == "" || source.SourceObservedUnixNanos <= 0 || source.ValidUntil.Before(got.ValidUntil) || len(source.Paths) != 2 {
				t.Fatal("public context lost complete original source or borrowed sibling authority", source)
			}
		}
		for _, path := range got.Paths {
			if path.Peer.Collector != "beta" || path.Path.Segments[1].Values[1] != uint32(64498+lane*10) {
				t.Fatal("public context selected less-specific or sibling paths", path)
			}
		}
		missing, err := read(tenant, scope, "203.0.113.1", profile)
		if !errors.Is(err, ErrBGPRoutingRouteMissing) || len(missing.Sources) != 2 || missing.Paths != nil || missing.Prefix.IsValid() || missing.Scope != scope || !missing.ValidUntil.After(missing.AsOf) {
			t.Fatal("public context lost complete no-prefix source provenance", missing, err)
		}
	}
	for lane, tenant := range f.tenants {
		assertOwned(tenant, lane)
	}
	a, b := f.tenants[0], f.tenants[1]
	if got, err := read(a, entity.Scope{TenantID: b, ContextID: f.contextID}, "192.0.2.9", profile); !errors.Is(err, entity.ErrScopeMismatch) || got.Sources != nil || got.Paths != nil {
		t.Fatal("public context accepted a foreign tenant before source reads", got, err)
	}
	if got, err := read(a, entity.Scope{TenantID: a, ContextID: uuid.NewString()}, "192.0.2.9", profile); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Sources != nil {
		t.Fatal("public context borrowed a source from another context", got, err)
	}
	low := profile
	low.MemoryBytes = 1024
	if got, err := read(a, entity.Scope{TenantID: a, ContextID: f.contextID}, "192.0.2.9", low); !errors.Is(err, ErrBGPRoutingBudget) || got.Sources != nil || got.Paths != nil {
		t.Fatal("public context returned a prefix after whole-cohort admission failed", got, err)
	}
	assign(a, "ris/mrt_table_dump_v2/pending")
	if got, err := read(a, entity.Scope{TenantID: a, ContextID: f.contextID}, "192.0.2.9", profile); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Sources != nil || got.Paths != nil {
		t.Fatal("public context published a partial assigned source cohort", got, err)
	}
	assertOwned(b, 1)
	write(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND context_id=$2 AND source_kind='public_bgp' AND source_ref='ris/mrt_table_dump_v2/pending'`, a, f.contextID)
		return err
	})
	assertOwned(a, 0)
	original, err := read(a, entity.Scope{TenantID: a, ContextID: f.contextID}, "192.0.2.9", profile)
	if err != nil {
		t.Fatal(err)
	}
	current := func(tenant string, public *BGPPublicContextLookup) bool {
		t.Helper()
		var allowed bool
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			allowed, err = routingPublicCaptureAuthorityCurrent(ctx, sc, entity.Scope{TenantID: tenant, ContextID: f.contextID}, public, false)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return allowed
	}
	// Rotate the source through its actual writer to a complete empty RIB.
	// Original captured authority must not require/refill from today's header.
	empty := BGPPublicSnapshotInput{CollectorAgentID: "role-listener", SenderSerial: f.serials[a+"role-listener"], SourceRef: refs[1], ObservationID: uuid.NewString(), ObservedAt: time.Now()}
	empty.SourceRecord = publicMRTRecordForTest(nil, true, false, uint32(empty.ObservedAt.Unix()))
	write(a, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (BGPRouting{}).StagePublicMRTSourceInScope(ctx, sc, empty, profile, true)
		if err == nil && got.Status != "staged" {
			t.Fatal("empty source rotation could not stage", got)
		}
		return err
	})
	// The authenticated receiver observes the message before opening its write
	// transaction. A timestamp minted inside the callback is after that
	// transaction's authority clock and must remain correctly refused.
	complete := BGPPublicSnapshotMessage{CollectorAgentID: empty.CollectorAgentID, SenderSerial: empty.SenderSerial, SourceRef: empty.SourceRef, SnapshotID: empty.ObservationID, Sequence: 1, ObservedAt: time.Now(), Complete: true}
	write(a, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, complete, nil, profile, time.Hour)
		if err == nil && got.Status != "applied" {
			t.Fatal("empty source rotation could not complete", got)
		}
		return err
	})
	if !current(a, &original) {
		t.Fatal("retained public authority incorrectly required a current original RIB")
	}
	rotated, err := read(a, original.Scope, "192.0.2.9", profile)
	if err != nil || len(rotated.Sources) != 2 || rotated.Prefix.String() != "192.0.2.0/24" || original.Prefix.String() != "192.0.2.0/25" {
		t.Fatal("public RIB rotation refilled original facts or lost its complete empty contributor", rotated, err)
	}
	write(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=clock_timestamp() WHERE tenant_id=$1 AND context_id=$2 AND source_kind='public_bgp' AND source_ref=$3`, a, f.contextID, refs[1])
		return err
	})
	if current(a, &original) {
		t.Fatal("retained public capture kept expired original source authority")
	}
	got, err := read(a, entity.Scope{TenantID: a, ContextID: f.contextID}, "192.0.2.9", profile)
	if err != nil || len(got.Sources) != 1 || got.Sources[0].Source.SourceRef != refs[0] || got.Prefix.String() != "192.0.2.0/24" {
		t.Fatal("public context retained an explicitly expired source assignment", got, err)
	}
	assertOwned(b, 1)
}
