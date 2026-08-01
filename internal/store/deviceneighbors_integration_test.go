// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration || isolation

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func deviceNeighborIsolationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testsupport.PostgresDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func TestDeviceNeighborEvidenceStorageIsTenantIsolatedAndBounded(t *testing.T) {
	ctx := context.Background()
	pool := deviceNeighborIsolationPool(t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA, err := NewTenants(pool).Create(ctx, "neighbors-a-"+suffix, "Neighbors A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, "neighbors-b-"+suffix, "Neighbors B")
	if err != nil {
		t.Fatal(err)
	}
	repo := NewDeviceNeighbors(pool)
	now := time.Now().UTC().Truncate(time.Second)
	write := func(tenant, address, remote string, count int) {
		t.Helper()
		snapshot := device.NeighborSnapshot{
			TenantID: tenant, AgentID: "agent-1", DeviceAddress: address,
			DeviceName: "core", ObservedAt: now,
		}
		for i := 0; i < count; i++ {
			snapshot.Neighbors = append(snapshot.Neighbors, device.NeighborEvidence{
				LocalPortID: fmt.Sprintf("port-%d", i), RemoteChassisID: remote,
				RemoteDeviceName: remote, RemotePortID: fmt.Sprintf("remote-%d", i),
				Protocol: device.NeighborProtocolLLDP, Confidence: 0.95,
				FreshUntil: now.Add(2 * time.Minute),
			})
		}
		if err := repo.ReplaceSnapshot(ctx, tenant, snapshot); err != nil {
			t.Fatalf("replace snapshot: %v", err)
		}
	}
	write(tenantA.ID, "10.0.0.1", "leaf-a", device.MaxNeighborsPerDevice+20)
	write(tenantB.ID, "10.0.0.2", "secret-leaf-b", 1)

	rowsA, truncated, err := repo.ListNeighbors(ctx, tenantA.ID, device.NeighborFilter{Limit: device.MaxNeighborRead})
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(rowsA) != device.MaxNeighborsPerDevice {
		t.Fatalf("tenant A rows=%d truncated=%v, want hard per-device cap %d", len(rowsA), truncated, device.MaxNeighborsPerDevice)
	}
	for _, row := range rowsA {
		if row.TenantID != tenantA.ID || row.RemoteDeviceName == "secret-leaf-b" {
			t.Fatalf("tenant A read cross-tenant row: %+v", row)
		}
	}
	rowsB, _, err := repo.ListNeighbors(ctx, tenantB.ID, device.NeighborFilter{})
	if err != nil || len(rowsB) != 1 || rowsB[0].RemoteDeviceName != "secret-leaf-b" {
		t.Fatalf("tenant B rows=%+v err=%v", rowsB, err)
	}

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM device_neighbor_evidence`).Scan(&count); err != nil {
				return err
			}
			if count != device.MaxNeighborsPerDevice {
				t.Fatalf("predicate-free forced-RLS count=%d, want %d", count, device.MaxNeighborsPerDevice)
			}
			tag, err := sc.Q.Exec(ctx, `DELETE FROM device_neighbor_evidence WHERE tenant_id=$1`, tenantB.ID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Fatal("tenant A deleted tenant B physical evidence")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
