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

	"github.com/imfeelingtheagi/probectl/internal/flow"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestFlowQualityReceiptStorageIsForcedRLSTenantIsolatedAndSecretFree(t *testing.T) {
	ctx := context.Background()
	pool := deviceNeighborIsolationPool(t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA, err := NewTenants(pool).Create(ctx, "flow-quality-a-"+suffix, "Flow Quality A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, "flow-quality-b-"+suffix, "Flow Quality B")
	if err != nil {
		t.Fatal(err)
	}
	repo := NewFlowQualityReceipts(pool)
	now := time.Now().UTC().Truncate(time.Second)
	write := func(tenant, agent, exporter string, at time.Time) {
		t.Helper()
		last := at.Add(-time.Second)
		receipt := flow.EvaluateQualityState(flow.QualityReceipt{
			TenantID: tenant, AgentID: agent, ExporterAddress: exporter,
			Protocol: flow.ProtoIPFIX, WindowStartedAt: at.Add(-time.Minute),
			WindowEndedAt: at, LastPacketAt: last, LastValidRecordAt: &last,
			PacketsReceived: 5, RecordsDecoded: 10,
			TemplateState: flow.QualityTemplateReady,
			SamplingState: flow.QualitySamplingUnsampled,
		}, at)
		if err := repo.UpsertQualityReceipt(ctx, tenant, receipt); err != nil {
			t.Fatalf("upsert quality receipt: %v", err)
		}
	}
	write(tenantA.ID, "agent-a", "192.0.2.10", now)
	write(tenantB.ID, "agent-b", "198.51.100.20", now)
	write(tenantA.ID, "agent-a", "192.0.2.10", now.Add(-time.Minute))

	rowsA, truncated, err := repo.ListQualityReceipts(ctx, tenantA.ID, flow.QualityFilter{})
	if err != nil || truncated || len(rowsA) != 1 ||
		rowsA[0].ExporterAddress != "192.0.2.10" ||
		rowsA[0].WindowEndedAt.Before(now) {
		t.Fatalf("tenant A rows=%+v truncated=%v err=%v", rowsA, truncated, err)
	}
	rowsB, _, err := repo.ListQualityReceipts(ctx, tenantB.ID, flow.QualityFilter{})
	if err != nil || len(rowsB) != 1 || rowsB[0].ExporterAddress != "198.51.100.20" {
		t.Fatalf("tenant B rows=%+v err=%v", rowsB, err)
	}

	boundaryAsOf := now.Add(time.Hour)
	boundaryLast := boundaryAsOf.Add(-flow.QualityStaleAfter)
	boundary := flow.EvaluateQualityState(flow.QualityReceipt{
		TenantID: tenantA.ID, AgentID: "agent-boundary", ExporterAddress: "192.0.2.99",
		Protocol: flow.ProtoIPFIX, WindowStartedAt: boundaryAsOf.Add(-4 * time.Minute),
		WindowEndedAt: boundaryAsOf, LastPacketAt: boundaryLast, LastValidRecordAt: &boundaryLast,
		PacketsReceived: 1, RecordsDecoded: 1,
		TemplateState: flow.QualityTemplateReady,
		SamplingState: flow.QualitySamplingUnsampled,
	}, boundaryAsOf)
	if err := repo.UpsertQualityReceipt(ctx, tenantA.ID, boundary); err != nil {
		t.Fatalf("upsert boundary receipt: %v", err)
	}
	healthy, _, err := repo.ListQualityReceipts(ctx, tenantA.ID, flow.QualityFilter{
		Exporter: boundary.ExporterAddress, State: flow.QualityStateHealthy, AsOf: boundaryAsOf,
	})
	if err != nil || len(healthy) != 1 || healthy[0].State != flow.QualityStateHealthy {
		t.Fatalf("healthy boundary rows=%+v err=%v", healthy, err)
	}
	staleAsOf := boundaryAsOf.Add(time.Nanosecond)
	stale, _, err := repo.ListQualityReceipts(ctx, tenantA.ID, flow.QualityFilter{
		Exporter: boundary.ExporterAddress, State: flow.QualityStateStale, AsOf: staleAsOf,
	})
	if err != nil || len(stale) != 1 || stale[0].State != flow.QualityStateStale {
		t.Fatalf("stale boundary rows=%+v err=%v", stale, err)
	}

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantA.ID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_ingest_quality_receipts`).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				t.Fatalf("predicate-free forced-RLS count=%d, want 1", count)
			}
			tag, err := sc.Q.Exec(ctx, `DELETE FROM flow_ingest_quality_receipts WHERE tenant_id=$1`, tenantB.ID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				t.Fatal("tenant A deleted tenant B flow quality receipt")
			}
			var forbidden int
			if err := sc.Q.QueryRow(ctx, `
				SELECT count(*)
				  FROM information_schema.columns
				 WHERE table_schema = current_schema()
				   AND table_name = 'flow_ingest_quality_receipts'
				   AND column_name IN (
				     'raw_datagram', 'source_address', 'destination_address',
				     'credential', 'password', 'error', 'error_text',
				     'rejected_source_address'
				   )
			`).Scan(&forbidden); err != nil {
				return err
			}
			if forbidden != 0 {
				t.Fatalf("receipt table exposes %d forbidden raw/secret columns", forbidden)
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}
