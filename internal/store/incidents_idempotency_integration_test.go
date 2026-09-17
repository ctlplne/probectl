// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-078: appending the same signal twice leaves one row and one count; the
// aggregates (signal_count, last_seen_at, severity) are not touched by the
// duplicate.
func TestAppendSignalIsIdempotentOnTheFingerprint(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	tn, err := NewTenants(pool).Create(ctx, fmt.Sprintf("sig-%d", time.Now().UnixNano()), "sig")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 17, 11, 5, 27, 0, time.UTC)
	sig := incident.Signal{TenantID: tn.ID, Plane: "bgp", Kind: "bgp.possible_hijack", Severity: incident.SeverityCritical,
		Title: "sub-prefix", Target: "216.75.128.0/25", Prefix: "216.75.128.0/25", OccurredAt: at,
		Attributes: map[string]string{"new_origin_asn": "65010"}}
	var id string
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		inc, err := (Incidents{}).Create(ctx, sc, incident.Incident{TenantID: tn.ID, Title: "hijack", Severity: incident.SeverityCritical,
			Status: incident.StatusOpen, StartedAt: at, LastSeenAt: at})
		if err != nil {
			return err
		}
		id = inc.ID
		for i := 0; i < 3; i++ {
			if _, err := (Incidents{}).AppendSignal(ctx, sc, id, sig); err != nil {
				return err
			}
		}
		return nil
	})
	inTenant(ctx, t, pool, tn.ID, func(ctx context.Context, sc tenancy.Scope) error {
		inc, err := (Incidents{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if inc.SignalCount != 1 || len(inc.Signals) != 1 {
			t.Fatalf("three identical appends must be one signal: count=%d rows=%d", inc.SignalCount, len(inc.Signals))
		}
		later := sig
		later.OccurredAt = at.Add(time.Minute)
		if _, err := (Incidents{}).AppendSignal(ctx, sc, id, later); err != nil {
			return err
		}
		inc, err = (Incidents{}).Get(ctx, sc, id)
		if err != nil {
			return err
		}
		if inc.SignalCount != 2 || !inc.LastSeenAt.Equal(later.OccurredAt) {
			t.Fatalf("a later occurrence is its own signal: count=%d last=%s", inc.SignalCount, inc.LastSeenAt)
		}
		return nil
	})
}
