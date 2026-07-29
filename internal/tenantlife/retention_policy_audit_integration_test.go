// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func appendRetentionPolicyAudit(
	actor, action string,
) RetentionAudit {
	return func(ctx context.Context, sc tenancy.Scope, p RetentionPolicy) error {
		_, err := audit.TenantAppend(ctx, sc, actor, action, p.TenantID, map[string]any{
			"flow_retention_days": p.FlowRetentionDays,
		})
		return err
	}
}

func tenantRetentionAuditCount(
	t *testing.T,
	engine *Engine,
	tenantID, action string,
) int64 {
	t.Helper()
	var count int64
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
	err := tenancy.InTenant(ctx, engine.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(
			ctx,
			`SELECT count(*)
			   FROM audit_events
			  WHERE tenant_id = $1
			    AND action = $2`,
			tenantID,
			action,
		).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count tenant retention audits: %v", err)
	}
	return count
}

func tenantRetentionPolicyRowCount(t *testing.T, engine *Engine, tenantID string) int64 {
	t.Helper()
	var count int64
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
	err := tenancy.InTenant(ctx, engine.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(
			ctx,
			`SELECT count(*) FROM tenant_retention WHERE tenant_id = $1`,
			tenantID,
		).Scan(&count)
	})
	if err != nil {
		t.Fatalf("count tenant retention policy rows: %v", err)
	}
	return count
}

func requireFlowRetentionDays(t *testing.T, engine *Engine, tenantID string, want int) {
	t.Helper()
	policy, err := engine.RetentionFor(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("read tenant %s retention policy: %v", tenantID, err)
	}
	if policy.FlowRetentionDays == nil || *policy.FlowRetentionDays != want {
		t.Fatalf(
			"tenant %s flow retention = %v, want %d",
			tenantID,
			policy.FlowRetentionDays,
			want,
		)
	}
}

func TestRetentionPolicyAuditAtomicRollbackAndTwoTenantIsolationPG(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "it-retention-a-"+stamp)
	tenantB := mkTenant(t, pool, "it-retention-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`,
			tenantA,
			tenantB,
		); err != nil {
			t.Errorf("cleanup retention-audit tenants: %v", err)
		}
	})

	engine := New(pool, nil, nil, nil, nil, "", testLog())
	oldA, oldB := 30, 60
	for _, fixture := range []struct {
		tenant string
		days   *int
	}{
		{tenant: tenantA, days: &oldA},
		{tenant: tenantB, days: &oldB},
	} {
		if err := engine.SetRetentionAudited(
			context.Background(),
			RetentionPolicy{
				TenantID:          fixture.tenant,
				FlowRetentionDays: fixture.days,
				UpdatedBy:         "fixture",
			},
			appendRetentionPolicyAudit("fixture", "fixture.retention_seed"),
		); err != nil {
			t.Fatalf("seed tenant retention: %v", err)
		}
	}

	wantAuditErr := errors.New("mandatory tenant audit unavailable")
	nextA := 14
	sawUncommittedUpsert := false
	err := engine.SetRetentionAudited(
		context.Background(),
		RetentionPolicy{
			TenantID:          tenantA,
			FlowRetentionDays: &nextA,
			UpdatedBy:         "tenant:" + tenantA,
		},
		func(ctx context.Context, sc tenancy.Scope, p RetentionPolicy) error {
			var inTxDays int
			if err := sc.Q.QueryRow(
				ctx,
				`SELECT flow_retention_days
				   FROM tenant_retention
				  WHERE tenant_id = $1`,
				tenantA,
			).Scan(&inTxDays); err != nil {
				return err
			}
			sawUncommittedUpsert = inTxDays == nextA
			if _, err := audit.TenantAppend(
				ctx,
				sc,
				"tenant-admin-a",
				"lifecycle.retention_set",
				p.TenantID,
				map[string]any{"flow_retention_days": p.FlowRetentionDays},
			); err != nil {
				return err
			}
			return wantAuditErr
		},
	)
	if !errors.Is(err, wantAuditErr) {
		t.Fatalf("failed audited retention update = %v, want %v", err, wantAuditErr)
	}
	if !sawUncommittedUpsert {
		t.Fatal("audit callback did not observe tenant A upsert in its transaction")
	}
	requireFlowRetentionDays(t, engine, tenantA, oldA)
	requireFlowRetentionDays(t, engine, tenantB, oldB)
	if got := tenantRetentionAuditCount(t, engine, tenantA, "lifecycle.retention_set"); got != 0 {
		t.Fatalf("rolled-back tenant A audit rows = %d, want 0", got)
	}
	if got := tenantRetentionAuditCount(t, engine, tenantB, "lifecycle.retention_set"); got != 0 {
		t.Fatalf("tenant B audit rows changed by tenant A failure: %d", got)
	}

	successAuditCalls := 0
	if err := engine.SetRetentionAudited(
		context.Background(),
		RetentionPolicy{
			TenantID:          tenantA,
			FlowRetentionDays: &nextA,
			UpdatedBy:         "tenant:" + tenantA,
		},
		func(ctx context.Context, sc tenancy.Scope, p RetentionPolicy) error {
			successAuditCalls++
			return appendRetentionPolicyAudit(
				"tenant-admin-a",
				"lifecycle.retention_set",
			)(ctx, sc, p)
		},
	); err != nil {
		t.Fatalf("successful audited retention update: %v", err)
	}
	requireFlowRetentionDays(t, engine, tenantA, nextA)
	requireFlowRetentionDays(t, engine, tenantB, oldB)
	if successAuditCalls != 1 {
		t.Fatalf("successful audit callback calls = %d, want 1", successAuditCalls)
	}
	if got := tenantRetentionAuditCount(t, engine, tenantA, "lifecycle.retention_set"); got != 1 {
		t.Fatalf("committed tenant A retention audits = %d, want 1", got)
	}
	if got := tenantRetentionAuditCount(t, engine, tenantB, "lifecycle.retention_set"); got != 0 {
		t.Fatalf("tenant B audit rows changed by tenant A success: %d", got)
	}
	if got := tenantRetentionPolicyRowCount(t, engine, tenantA); got != 1 {
		t.Fatalf("tenant A policy rows = %d, want exactly 1", got)
	}
	if got := tenantRetentionPolicyRowCount(t, engine, tenantB); got != 1 {
		t.Fatalf("tenant B policy rows = %d, want exactly 1", got)
	}
	for _, tenantID := range []string{tenantA, tenantB} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
		if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return audit.TenantVerify(ctx, sc)
		}); err != nil {
			t.Fatalf("tenant %s audit chain after rollback/success: %v", tenantID, err)
		}
	}
}
