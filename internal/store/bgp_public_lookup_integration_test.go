// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func publicSnapshotReadForFixture(t *testing.T, f *roleInputsFixture, tenant string, input BGPPublicSnapshotInput, id, address string, profile BGPRoutingBudget, maxAge time.Duration) (BGPPublicRoutingLookup, error) {
	t.Helper()
	source := BGPPublicRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, CollectorAgentID: input.CollectorAgentID, SourceRef: input.SourceRef, SenderSerial: f.serials[tenant+"role-listener"], ObservedAt: time.Now()}
	var got BGPPublicRoutingLookup
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		got, err = (BGPRouting{}).LookupPublicSnapshotInScope(ctx, sc, source, id, netip.MustParseAddr(address), profile, maxAge)
		return err
	})
	return got, err
}

func provePublishedPublicSnapshotRead(t *testing.T, f *roleInputsFixture, tenant string, input BGPPublicSnapshotInput, staged BGPPublicSnapshotStageResult, profile BGPRoutingBudget) {
	t.Helper()
	for _, tc := range []struct {
		address, prefix string
		paths           int
	}{{"192.0.2.9", "192.0.2.0/24", 1}, {"2001:db8::1", "2001:db8::/32", 2}} {
		got, err := publicSnapshotReadForFixture(t, f, tenant, input, staged.ID, tc.address, profile, time.Hour)
		if err != nil || got.Source.TenantID != tenant || got.Source.ContextID != f.contextID || got.SnapshotID != staged.ID || got.Prefix.String() != tc.prefix || len(got.Paths) != tc.paths || got.SourceObservedUnixNanos != *input.SourceObservedUnixNanos || got.ValidUntil.After(time.Unix(0, *input.SourceObservedUnixNanos).Add(time.Hour)) {
			t.Fatal("public reader lost complete dual-family paths or original source authority", got, err)
		}
		seen := map[string]bool{}
		for _, path := range got.Paths {
			if seen[path.View.ID] || path.Peer.Collector == "" || len(path.Path.Segments) != 3 || path.Path.Segments[0].Kind != 3 || path.Path.Segments[2].Kind != 1 {
				t.Fatal("public reader discarded a peer or complete path kinds", path)
			}
			seen[path.View.ID] = true
		}
	}
	for _, tc := range []struct {
		address string
		age     time.Duration
		want    error
	}{{"203.0.113.1", time.Hour, ErrBGPRoutingRouteMissing}, {"192.0.2.9", time.Nanosecond, ErrBGPRoutingSourceUnavailable}} {
		if got, err := publicSnapshotReadForFixture(t, f, tenant, input, staged.ID, tc.address, profile, tc.age); !errors.Is(err, tc.want) || got.Paths != nil {
			t.Fatal("public reader manufactured missing or stale source data", got, err)
		} else if errors.Is(err, ErrBGPRoutingRouteMissing) && (got.Source.TenantID != tenant || got.Source.ContextID != f.contextID || got.SnapshotID != staged.ID || got.SourceObservedUnixNanos != *input.SourceObservedUnixNanos || got.AsOf.IsZero() || !got.ValidUntil.After(got.AsOf) || got.ValidUntil.After(time.Unix(0, *input.SourceObservedUnixNanos).Add(tc.age)) || got.Prefix.IsValid()) {
			t.Fatal("complete public no-prefix result discarded its original source authority", got)
		}
	}
}
