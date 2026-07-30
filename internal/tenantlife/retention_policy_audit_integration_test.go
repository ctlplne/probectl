// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

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

type retentionPolicyState struct {
	FlowDays      int
	PolicyRows    int64
	AuditRows     int64
	HeadSeq       int64
	HeadHash      string
	PrunedSeq     int64
	PrunedHash    string
	RetentionRows int64
}

func tenantRetentionState(t *testing.T, engine *Engine, tenantID string) retentionPolicyState {
	t.Helper()
	var got retentionPolicyState
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
	err := tenancy.InTenant(ctx, engine.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := sc.Q.QueryRow(
			ctx,
			`SELECT flow_retention_days FROM tenant_retention WHERE tenant_id = $1`,
			tenantID,
		).Scan(&got.FlowDays); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(
			ctx,
			`SELECT count(*) FROM tenant_retention WHERE tenant_id = $1`,
			tenantID,
		).Scan(&got.PolicyRows); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(
			ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE action = 'lifecycle.retention_set')
			   FROM audit_events
			  WHERE tenant_id = $1`,
			tenantID,
		).Scan(&got.AuditRows, &got.RetentionRows); err != nil {
			return err
		}
		return sc.Q.QueryRow(
			ctx,
			`SELECT head_seq, head_hash, pruned_seq, pruned_hash
			   FROM audit_stream_heads
			  WHERE tenant_id = $1`,
			tenantID,
		).Scan(&got.HeadSeq, &got.HeadHash, &got.PrunedSeq, &got.PrunedHash)
	})
	if err != nil {
		t.Fatalf("snapshot tenant %s retention state: %v", tenantID, err)
	}
	return got
}

func requireRetentionState(
	t *testing.T,
	engine *Engine,
	tenantID string,
	want retentionPolicyState,
) {
	t.Helper()
	if got := tenantRetentionState(t, engine, tenantID); !reflect.DeepEqual(got, want) {
		t.Fatalf("tenant %s state changed:\n got  %+v\n want %+v", tenantID, got, want)
	}
}

func latestRetentionAudit(t *testing.T, engine *Engine, tenantID string) audit.Event {
	t.Helper()
	var ev audit.Event
	var dataJSON []byte
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
	err := tenancy.InTenant(ctx, engine.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(
			ctx,
			`SELECT seq, actor, action, target, data::text, prev_hash, hash, created_at
			   FROM audit_events
			  WHERE tenant_id = $1
			    AND action = 'lifecycle.retention_set'
			  ORDER BY seq DESC
			  LIMIT 1`,
			tenantID,
		).Scan(
			&ev.Seq,
			&ev.Actor,
			&ev.Action,
			&ev.Target,
			&dataJSON,
			&ev.PrevHash,
			&ev.Hash,
			&ev.CreatedAt,
		)
	})
	if err != nil {
		t.Fatalf("read latest retention audit for tenant %s: %v", tenantID, err)
	}
	if err := json.Unmarshal(dataJSON, &ev.Data); err != nil {
		t.Fatalf("decode latest retention audit data: %v", err)
	}
	return ev
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

func TestRetentionAuditMandatoryFixedRollbackAndPooledIsolationPG(t *testing.T) {
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
		days   int
	}{
		{tenant: tenantA, days: oldA},
		{tenant: tenantB, days: oldB},
	} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(fixture.tenant))
		if err := engine.SetRetention(
			ctx,
			RetentionPolicy{
				TenantID:          fixture.tenant,
				FlowRetentionDays: &fixture.days,
				UpdatedBy:         "fixture",
			},
			"fixture",
		); err != nil {
			t.Fatalf("seed tenant retention: %v", err)
		}
	}
	baseA := tenantRetentionState(t, engine, tenantA)
	baseB := tenantRetentionState(t, engine, tenantB)

	wantAuditErr := errors.New("mandatory tenant audit unavailable")
	nextA := 14
	sawUncommittedUpsert := false
	appendCalls := 0
	engine.appendRetentionPolicyAudit = func(
		ctx context.Context,
		sc tenancy.Scope,
		actor, action, target string,
		data map[string]any,
	) (audit.Event, error) {
		appendCalls++
		if actor != "tenant-admin-a" ||
			action != retentionPolicyAuditAction ||
			target != tenantA ||
			data["flow_retention_days"] != &nextA {
			return audit.Event{}, fmt.Errorf(
				"unexpected fixed audit input actor=%q action=%q target=%q data=%+v",
				actor,
				action,
				target,
				data,
			)
		}
		var inTxDays int
		if err := sc.Q.QueryRow(
			ctx,
			`SELECT flow_retention_days
			   FROM tenant_retention
			  WHERE tenant_id = $1`,
			tenantA,
		).Scan(&inTxDays); err != nil {
			return audit.Event{}, err
		}
		sawUncommittedUpsert = inTxDays == nextA
		return audit.Event{}, wantAuditErr
	}
	err := engine.SetRetention(
		tenancy.WithTenant(context.Background(), tenancy.ID(tenantA)),
		RetentionPolicy{
			TenantID:          tenantA,
			FlowRetentionDays: &nextA,
			UpdatedBy:         "tenant:" + tenantA,
		},
		" tenant-admin-a ",
	)
	if !errors.Is(err, wantAuditErr) {
		t.Fatalf("failed audited retention update = %v, want %v", err, wantAuditErr)
	}
	if appendCalls != 1 {
		t.Fatalf("failed audit append calls = %d, want exactly 1", appendCalls)
	}
	if !sawUncommittedUpsert {
		t.Fatal("audit appender did not observe tenant A upsert in its transaction")
	}
	requireRetentionState(t, engine, tenantA, baseA)
	requireRetentionState(t, engine, tenantB, baseB)

	engine.appendRetentionPolicyAudit = audit.TenantAppend
	otelDays, ebpfDays, pathDays := 13, 12, 11
	auditDays, aiDays, objectDays, identityDays := 10, 9, 8, 7
	policy := RetentionPolicy{
		TenantID:                     tenantA,
		FlowRetentionDays:            &nextA,
		OtelRetentionDays:            &otelDays,
		EBPFRetentionDays:            &ebpfDays,
		PathRetentionDays:            &pathDays,
		AuditRetentionDays:           &auditDays,
		AIAnswerRetentionDays:        &aiDays,
		ObjectRetentionDays:          &objectDays,
		DerivedIdentityRetentionDays: &identityDays,
		UpdatedBy:                    "tenant:" + tenantA,
	}
	if err := engine.SetRetention(
		tenancy.WithTenant(context.Background(), tenancy.ID(tenantA)),
		policy,
		" tenant-admin-a ",
	); err != nil {
		t.Fatalf("successful audited retention update: %v", err)
	}
	gotA := tenantRetentionState(t, engine, tenantA)
	if gotA.FlowDays != nextA || gotA.PolicyRows != 1 {
		t.Fatalf("tenant A committed policy state = %+v", gotA)
	}
	if gotA.AuditRows != baseA.AuditRows+1 ||
		gotA.RetentionRows != baseA.RetentionRows+1 ||
		gotA.HeadSeq != baseA.HeadSeq+1 ||
		gotA.HeadHash == baseA.HeadHash ||
		gotA.PrunedSeq != baseA.PrunedSeq ||
		gotA.PrunedHash != baseA.PrunedHash {
		t.Fatalf("tenant A atomic policy/audit state = %+v, base %+v", gotA, baseA)
	}
	requireRetentionState(t, engine, tenantB, baseB)

	ev := latestRetentionAudit(t, engine, tenantA)
	wantData := map[string]any{
		"flow_retention_days":             float64(nextA),
		"otel_retention_days":             float64(otelDays),
		"ebpf_retention_days":             float64(ebpfDays),
		"path_retention_days":             float64(pathDays),
		"audit_retention_days":            float64(auditDays),
		"ai_answer_retention_days":        float64(aiDays),
		"object_retention_days":           float64(objectDays),
		"derived_identity_retention_days": float64(identityDays),
	}
	if ev.Actor != "tenant-admin-a" ||
		ev.Action != retentionPolicyAuditAction ||
		ev.Target != tenantA ||
		!reflect.DeepEqual(ev.Data, wantData) {
		t.Fatalf("fixed retention audit = %+v, want actor/action/target/data exact", ev)
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

func TestRetentionTenantMismatchPooledIsolation(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "it-retention-mismatch-a-"+stamp)
	tenantB := mkTenant(t, pool, "it-retention-mismatch-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`,
			tenantA,
			tenantB,
		); err != nil {
			t.Errorf("cleanup retention mismatch tenants: %v", err)
		}
	})

	engine := New(pool, nil, nil, nil, nil, "", testLog())
	oldA, oldB := 30, 60
	for _, fixture := range []struct {
		tenant string
		days   int
	}{
		{tenant: tenantA, days: oldA},
		{tenant: tenantB, days: oldB},
	} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(fixture.tenant))
		if err := engine.SetRetention(
			ctx,
			RetentionPolicy{
				TenantID:          fixture.tenant,
				FlowRetentionDays: &fixture.days,
				UpdatedBy:         "fixture",
			},
			"fixture",
		); err != nil {
			t.Fatalf("seed tenant retention: %v", err)
		}
	}
	baseA := tenantRetentionState(t, engine, tenantA)
	baseB := tenantRetentionState(t, engine, tenantB)
	nextB := 14
	err := engine.SetRetention(
		tenancy.WithTenant(context.Background(), tenancy.ID(tenantA)),
		RetentionPolicy{TenantID: tenantB, FlowRetentionDays: &nextB, UpdatedBy: "tenant:" + tenantA},
		"tenant-admin-a",
	)
	if err == nil {
		t.Fatal("tenant-A context accepted a tenant-B retention policy")
	}
	requireRetentionState(t, engine, tenantA, baseA)
	requireRetentionState(t, engine, tenantB, baseB)
}
