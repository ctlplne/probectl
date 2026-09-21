// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestAgentVersionIsRecordedFromBatchesAndHeartbeats (DPR-093): a collector
// registered without a version gets one from its first verified batch, keeps
// it while unchanged, follows an upgrade, and a versioned heartbeat (the BMP
// listener) records liveness and version in one touch.
func TestAgentVersionIsRecordedFromBatchesAndHeartbeats(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant, err := NewTenants(pool).Create(ctx, "ver-"+suffix, "Version "+suffix)
	if err != nil {
		t.Fatal(err)
	}
	id := "00000000-0000-4000-8000-" + suffix[len(suffix)-12:]
	inTenant(ctx, t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (Agents{}).Register(ctx, sc, id, "flow-collector", "host", "", "spiffe://probectl/tenant/"+tenant.ID+"/agent/"+id, []string{"collector", "flow"}); err != nil {
			return err
		}
		version := func() string {
			a, err := (Agents{}).Get(ctx, sc, id)
			if err != nil {
				t.Fatal(err)
			}
			return a.AgentVersion
		}
		if v := version(); v != "" {
			t.Fatalf("a bus collector registers without a version, got %q", v)
		}
		if err := (Agents{}).RecordVersion(ctx, sc, id, "0.6.0"); err != nil {
			return err
		}
		if v := version(); v != "0.6.0" {
			t.Fatalf("first verified batch must record the version, got %q", v)
		}
		if err := (Agents{}).RecordVersion(ctx, sc, id, ""); err != nil {
			return err
		}
		if v := version(); v != "0.6.0" {
			t.Fatalf("an empty report must not erase the version, got %q", v)
		}
		if err := (Agents{}).RecordVersion(ctx, sc, id, "0.6.1"); err != nil {
			return err
		}
		if v := version(); v != "0.6.1" {
			t.Fatalf("an upgrade must be followed, got %q", v)
		}
		a, err := (Agents{}).HeartbeatVersion(ctx, sc, id, "0.6.2")
		if err != nil {
			return err
		}
		if a.AgentVersion != "0.6.2" || a.Status != "online" || a.LastSeenAt == nil {
			t.Fatalf("versioned heartbeat must record liveness and version: %+v", a)
		}
		if a, err := (Agents{}).HeartbeatVersion(ctx, sc, id, ""); err != nil || a.AgentVersion != "0.6.2" {
			t.Fatalf("a heartbeat without a version keeps the last one: %+v err=%v", a, err)
		}
		return nil
	})
}
