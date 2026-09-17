//go:build integration

// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-067: the published active set and heartbeat are tenant-scoped by forced
// RLS and replaced atomically per pass.
func TestAlertActiveStateReplaceListStatusIsolation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "alert-a-"+suffix, "alert-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "alert-b-"+suffix, "alert-b")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	items := []alert.ActiveAlert{{Fingerprint: "fp1", RuleID: "r1", RuleName: "checkout-down", Severity: alert.SeverityCritical,
		Metric: "probectl_probe_success", Labels: map[string]string{"canary_type": "http"}, Value: 0, Reason: "0 < 1", Since: now, LastSeenAt: now}}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		return (AlertActiveState{}).Replace(ctx, sc, items, now, 30*time.Second)
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (AlertActiveState{}).List(ctx, sc)
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0].Fingerprint != "fp1" || got[0].Labels["canary_type"] != "http" || got[0].Severity != alert.SeverityCritical {
			t.Fatalf("tenant A active = %+v", got)
		}
		at, interval, ok, err := (AlertActiveState{}).Status(ctx, sc)
		if err != nil || !ok || !at.Equal(now) || interval != 30*time.Second {
			t.Fatalf("status = %v %v %v %v", at, interval, ok, err)
		}
		return nil
	})
	inTenant(ctx, t, pool, b.ID, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := (AlertActiveState{}).List(ctx, sc)
		if err != nil || len(got) != 0 {
			t.Fatalf("tenant B sees tenant A's alerts: %+v err=%v", got, err)
		}
		if _, _, ok, err := (AlertActiveState{}).Status(ctx, sc); err != nil || ok {
			t.Fatalf("tenant B has a heartbeat it never published: ok=%v err=%v", ok, err)
		}
		return nil
	})
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if err := (AlertActiveState{}).Replace(ctx, sc, nil, now.Add(time.Minute), 30*time.Second); err != nil {
			return err
		}
		got, err := (AlertActiveState{}).List(ctx, sc)
		if err != nil || len(got) != 0 {
			t.Fatalf("replace with an empty set left rows: %+v err=%v", got, err)
		}
		return nil
	})
}
