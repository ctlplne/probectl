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
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publishPublicFlowFixture(t *testing.T, f *roleInputsFixture, tenant string, tail uint32, empty bool) string {
	t.Helper()
	const reference = "ris/mrt_table_dump_v2/rrc00"
	profile := publicCaptureBudget()
	profile.LeaseDuration = 12 * time.Hour
	write := func(fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error { return tenancy.InTenant(ctx, f.pool, fn) }); err != nil {
			t.Fatal(err)
		}
	}
	write(func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'role-listener','public_bgp',$2,$3) ON CONFLICT DO NOTHING`, tenant, reference, f.contextID)
		return err
	})
	input := BGPPublicSnapshotInput{CollectorAgentID: "role-listener", SenderSerial: f.serials[tenant+"role-listener"], SourceRef: reference, ObservationID: uuid.NewString(), ObservedAt: time.Now()}
	view := append(bytes.Repeat([]byte{0, 255}, 32767), 0)
	input.SourceRecord = publicMRTRecordForTest(view, empty, true, uint32(input.ObservedAt.Unix()))
	write(func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (BGPRouting{}).StagePublicMRTSourceInScope(ctx, sc, input, profile, true)
		if err == nil && got.Status != "staged" {
			t.Fatal("public flow fixture failed complete staging", got)
		}
		return err
	})
	families := []uint16{1, 2, 0}
	if empty {
		families = []uint16{0}
	}
	for i, afi := range families {
		message := BGPPublicSnapshotMessage{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: reference, SnapshotID: input.ObservationID, Sequence: int64(i + 1), ObservedAt: time.Now(), Complete: afi == 0}
		var record []byte
		if afi != 0 {
			record = publicMRTRIBRecordForTest(afi, tail, 0, uint32(input.ObservedAt.Unix()), false)
		}
		write(func(ctx context.Context, sc tenancy.Scope) error {
			got, err := (BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, message, record, profile, 12*time.Hour)
			if err == nil && got.Status != "applied" {
				t.Fatal("public flow fixture failed complete publication", got)
			}
			return err
		})
	}
	return input.ObservationID
}

// Real app-role TLS Postgres, registry writers, raw first-ingestion capture,
// authenticated publisher and current retained reader. Senders are modeled;
// separate mTLS/physical-flow and served-surface qualification remain required.
func TestPublicFlowFallbackKeepsOriginalCaptureAndCurrentTenantSourceAuthority(t *testing.T) {
	f, _, _, routerInput := newRoutingFlowCaptureFixture(t)
	profile := publicCaptureBudget()
	input := routerInput
	input.Source, input.Destination = netip.MustParseAddr("192.0.2.9"), netip.MustParseAddr("2001:db8::9")
	var original [2]string
	var references [2]BGPRoutingCaptureReference
	var raw = [32]byte{1, 2, 255}
	rpki := routingRPKIEnricher(t, time.Now(), `{"prefix":"192.0.2.0/24","asn":64497,"maxLength":32},{"prefix":"2001:db8::/32","asn":64497,"maxLength":128}`)
	captures := NewBGPRoutingFlowCaptures(f.pool).WithRPKIEnrichment(rpki)
	for lane, tenant := range f.tenants {
		original[lane] = publishPublicFlowFixture(t, f, tenant, uint32(64497+lane), false)
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		var selected BGPRoutingFlowLookup
		if err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			selected, err = (BGPRouting{}).LookupFlowInScope(ctx, sc, routerInput, profile)
			return err
		}); err != nil || selected.Source.State != "router_selected" || selected.Source.Public != nil {
			t.Fatal("public sources displaced the owned router-selected route", selected, err)
		}
		staged, err := captures.StageRaw(ctx, "routing-flow", []entity.FlowCaptureWitness{{RawDigest: raw, Input: input}}, profile)
		if err != nil || len(staged) != 1 || staged[0].Key == ([32]byte{}) || staged[0].CapturedAt.IsZero() {
			t.Fatal("public fallback could not retain its original raw candidate", staged, err)
		}
		references[lane], err = captures.CaptureAuthenticated(ctx, "routing-flow", raw, input, profile)
		if err != nil || references[lane].Key != staged[0].Key || !references[lane].CapturedAt.Equal(staged[0].CapturedAt) {
			t.Fatal("public authenticated capture lost its original clock or positive receipt", references[lane], err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var outcome string
			if err := sc.Q.QueryRow(ctx, `SELECT outcome FROM bgp_flow_capture_receipts WHERE tenant_id=$1 AND flow_key=$2`, tenant, references[lane].Key[:]).Scan(&outcome); err != nil {
				return err
			}
			if outcome != "captured" {
				t.Fatal("public authenticated publisher did not retain a positive terminal receipt", outcome)
			}
			return nil
		})
	}
	read := func(lane int) (BGPRoutingFlowLookup, error) {
		var got BGPRoutingFlowLookup
		tenant := f.tenants[lane]
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			got, err = (BGPRouting{}).readFlowCaptureInScope(ctx, sc, "routing-flow", entity.FlowCaptureWitness{RawDigest: raw, Input: input}, references[lane], profile, func(_ context.Context, record entity.ContextRecord) error {
				if record.TenantID != tenant || record.ContextID != f.contextID {
					t.Fatal("public capture authorized a foreign context")
				}
				return nil
			})
			return err
		})
		return got, err
	}
	assertOriginal := func(lane int) {
		t.Helper()
		got, err := read(lane)
		if err != nil || got.Owner.TenantID != f.tenants[lane] || got.Source.State != "public_fallback" || got.Destination.State != "public_fallback" || got.Source.RouterState != "no_prefix" || got.Source.Public == nil || got.Destination.Public == nil || got.Source.Public.Sources[0].SnapshotID != original[lane] || len(got.Source.Public.Paths) != 2 || len(got.Destination.Public.Paths) != 1 || len(got.Source.Public.Paths[0].Peer.ViewName) != 65535 || got.Source.Public.Paths[0].Path.Segments[1].Values[1] != uint32(64497+lane) {
			t.Fatal("public fallback lost original complete paths or crossed tenants", got, err)
		}
		if got.Source.RPKI == nil || got.Destination.RPKI == nil || got.Source.RPKI.Records != 2 || len(got.Source.RPKI.Covering) != 1 || len(got.Destination.RPKI.Covering) != 1 || got.Source.RPKI.Version != rpki.RPKI(got.CapturedAt).Version {
			t.Fatal("authenticated public flow omitted original complete validator evidence")
		}
		projection, err := routingCaptureQueryProjection(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), got, references[lane], profile)
		if err != nil || projection.Fields["src_bgp_provenance"] != "public_ris" || projection.Fields["src_bgp_prefix"] != "192.0.2.0/24" || projection.Fields["dst_bgp_prefix"] != "2001:db8::/32" || projection.Fields["src_bgp_rpki"] != "unknown" {
			t.Fatal("public retained native fields lost original provenance or invented RPKI", projection, err)
		}
	}
	assertOriginal(0)
	assertOriginal(1)
	// Replace A's current public RIB with a genuine complete empty source.
	// Its existing captured paths and clock must remain original, never refill.
	publishPublicFlowFixture(t, f, f.tenants[0], 64599, true)
	assertOriginal(0)
	assertOriginal(1)
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND context_id=$2 AND source_kind='public_bgp'`, f.tenants[0], f.contextID)
		return err
	})
	if got, err := read(0); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Owner.TenantID != "" {
		t.Fatal("public retained reader bypassed current original source authority", got, err)
	}
	assertOriginal(1)
}
