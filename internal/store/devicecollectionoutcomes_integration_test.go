// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDeviceCollectionOutcomeStorageIsTenantIsolatedBoundedAndSecretFree(t *testing.T) {
	ctx := context.Background()
	pool := deviceNeighborIsolationPool(t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA, err := NewTenants(pool).Create(ctx, "outcomes-a-"+suffix, "Outcomes A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, "outcomes-b-"+suffix, "Outcomes B")
	if err != nil {
		t.Fatal(err)
	}
	repo := NewDeviceCollectionOutcomes(pool)
	now := time.Now().UTC().Truncate(time.Second)
	write := func(tenant, agent, target, protocol, state, reason, action string, at time.Time) {
		t.Helper()
		outcome := device.CollectionOutcome{
			TenantID: tenant, AgentID: agent, ConfiguredTarget: target,
			Protocol: protocol, LastAttemptAt: &at, State: state,
			Reason: reason, NextAction: action,
		}
		if state == device.CollectionStateOKWithRows {
			outcome.RowCount = 1
			outcome.LastSuccessAt = &at
		}
		if state == device.CollectionStateHealthyEmpty {
			outcome.LastSuccessAt = &at
		}
		if err := repo.UpsertCollectionOutcome(ctx, tenant, outcome); err != nil {
			t.Fatalf("upsert outcome: %v", err)
		}
	}
	write(tenantA.ID, "agent-a", "router-a.internal", device.NeighborProtocolLLDP,
		device.CollectionStateOKWithRows, device.CollectionReasonRowsObserved,
		device.CollectionActionReviewEvidence, now)
	write(tenantB.ID, "agent-b", "secret-router-b.internal", device.NeighborProtocolCDP,
		device.CollectionStateFailed, device.CollectionReasonPollFailed,
		device.CollectionActionVerifyLocalAccess, now)

	// Older redelivery is idempotent and cannot replace a newer receipt.
	write(tenantA.ID, "agent-a", "router-a.internal", device.NeighborProtocolLLDP,
		device.CollectionStateFailed, device.CollectionReasonPollFailed,
		device.CollectionActionVerifyLocalAccess, now.Add(-time.Minute))

	rowsA, truncated, err := repo.ListCollectionOutcomes(ctx, tenantA.ID, device.CollectionOutcomeFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(rowsA) != 1 || rowsA[0].State != device.CollectionStateOKWithRows ||
		rowsA[0].ConfiguredTarget == "secret-router-b.internal" {
		t.Fatalf("tenant A receipt=%+v truncated=%v", rowsA, truncated)
	}
	rowsB, _, err := repo.ListCollectionOutcomes(ctx, tenantB.ID, device.CollectionOutcomeFilter{})
	if err != nil || len(rowsB) != 1 || rowsB[0].ConfiguredTarget != "secret-router-b.internal" {
		t.Fatalf("tenant B receipt=%+v err=%v", rowsB, err)
	}

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM device_collection_outcomes`).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				t.Fatalf("predicate-free forced-RLS count=%d, want 1", count)
			}
			tag, err := sc.Q.Exec(ctx, `DELETE FROM device_collection_outcomes WHERE tenant_id=$1`, tenantB.ID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Fatal("tenant A deleted tenant B collection receipt")
			}
			var rawCredentialColumns int
			if err := sc.Q.QueryRow(ctx, `
				SELECT count(*)
				  FROM information_schema.columns
				 WHERE table_schema = current_schema()
				   AND table_name = 'device_collection_outcomes'
				   AND column_name IN ('credential', 'community', 'username', 'password', 'raw_varbinds')
			`).Scan(&rawCredentialColumns); err != nil {
				return err
			}
			if rawCredentialColumns != 0 {
				t.Fatalf("receipt table exposes %d credential/raw evidence columns", rawCredentialColumns)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
