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

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
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

func TestTenantAuditRetentionEffectivePrunePooledIsolationPG(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "it-audit-retention-effective-a-"+stamp)
	tenantB := mkTenant(t, pool, "it-audit-retention-effective-b-"+stamp)
	tenantStale := mkTenant(t, pool, "it-audit-retention-effective-stale-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2 OR id = $3`,
			tenantA,
			tenantB,
			tenantStale,
		); err != nil {
			t.Errorf("cleanup effective retention tenants: %v", err)
		}
	})

	now := time.Now().UTC()
	for _, tenantID := range []string{tenantA, tenantB, tenantStale} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := audit.TenantAppend(
					ctx,
					sc,
					"retention-fixture",
					"retention.old.exported",
					tenantID,
					nil,
				); err != nil {
					return err
				}
				return (store.SIEMDelivery{}).Advance(ctx, sc, 1)
			},
		)
		if err != nil {
			t.Fatalf("seed tenant %s audit stream: %v", tenantID, err)
		}
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2 OR tenant_id = $3`,
		now.Add(-40*24*time.Hour),
		tenantA,
		tenantB,
	); err != nil {
		t.Fatalf("backdate tenant audit fixtures: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2`,
		now.Add(-400*24*time.Hour),
		tenantStale,
	); err != nil {
		t.Fatalf("backdate stale-policy audit fixture: %v", err)
	}

	const deploymentWindow = 365 * 24 * time.Hour
	engine := New(pool, nil, nil, nil, nil, "", testLog()).
		WithAuditRetentionMaximum(deploymentWindow)
	thirtyDays := 30
	if err := engine.SetRetention(
		tenancy.WithTenant(ctx, tenancy.ID(tenantA)),
		RetentionPolicy{
			TenantID:           tenantA,
			AuditRetentionDays: &thirtyDays,
			UpdatedBy:          "tenant-a-admin",
		},
		"tenant-a-admin",
	); err != nil {
		t.Fatalf("set tenant A audit retention: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO public.tenant_retention
		    (tenant_id, audit_retention_days, updated_by)
		 VALUES ($1, $2, 'legacy-fixture')
		 ON CONFLICT (tenant_id) DO UPDATE
		    SET audit_retention_days = EXCLUDED.audit_retention_days,
		        updated_by = EXCLUDED.updated_by,
		        updated_at = now()`,
		tenantStale,
		int(maxAuditRetentionDays+1),
	); err != nil {
		t.Fatalf("seed stale oversized audit retention: %v", err)
	}

	windowA, err := engine.ProviderAuditRetentionWindowFor(ctx, tenantA)
	if err != nil || windowA != 30*24*time.Hour {
		t.Fatalf("provider policy read A = (%v, %v), want (720h, nil)", windowA, err)
	}
	windowB, err := engine.ProviderAuditRetentionWindowFor(ctx, tenantB)
	if err != nil || windowB != 0 {
		t.Fatalf("provider policy read B = (%v, %v), want inherited zero", windowB, err)
	}
	windowStale, err := engine.ProviderAuditRetentionWindowFor(ctx, tenantStale)
	if err != nil || windowStale != deploymentWindow {
		t.Fatalf(
			"provider stale policy read = (%v, %v), want deployment clamp (%v, nil)",
			windowStale,
			err,
			deploymentWindow,
		)
	}

	runner := audit.NewRetentionRunnerPG(
		pool,
		audit.RetentionPolicy{Window: deploymentWindow},
		nil,
		testLog(),
	).WithTenantRetentionWindow(engine.ProviderAuditRetentionWindowFor).
		WithTenantIDsForTest(func(context.Context) ([]string, error) {
			return []string{tenantA, tenantB, tenantStale}, nil
		}).
		WithNowForTest(func() time.Time { return now })
	summary, err := runner.Tick(ctx)
	if err != nil {
		t.Fatalf("run effective tenant audit retention: %v", err)
	}
	if summary.TenantPruned != 2 || summary.TenantsChecked != 3 ||
		summary.ProviderPruned != 0 {
		t.Fatalf("effective tenant retention summary = %+v, want A plus stale/global prune", summary)
	}

	for _, tc := range []struct {
		tenant          string
		wantOld         int64
		wantPruneEvents int64
	}{
		{tenant: tenantA, wantOld: 0, wantPruneEvents: 1},
		{tenant: tenantB, wantOld: 1, wantPruneEvents: 0},
		{tenant: tenantStale, wantOld: 0, wantPruneEvents: 1},
	} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tc.tenant)),
			pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				var oldRows, pruneEvents int64
				if err := sc.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM audit_events
					  WHERE tenant_id = $1 AND action = 'retention.old.exported'`,
					tc.tenant,
				).Scan(&oldRows); err != nil {
					return err
				}
				if err := sc.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM audit_events
					  WHERE tenant_id = $1 AND action = $2`,
					tc.tenant,
					audit.RetentionPruneAction,
				).Scan(&pruneEvents); err != nil {
					return err
				}
				if oldRows != tc.wantOld || pruneEvents != tc.wantPruneEvents {
					return fmt.Errorf(
						"tenant %s old/prune rows = %d/%d, want %d/%d",
						tc.tenant,
						oldRows,
						pruneEvents,
						tc.wantOld,
						tc.wantPruneEvents,
					)
				}
				return audit.TenantVerify(ctx, sc)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	var receiptWindow string
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantA)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(
				ctx,
				`SELECT data->>'retention_window'
				   FROM audit_events
				  WHERE tenant_id = $1 AND action = $2`,
				tenantA,
				audit.RetentionPruneAction,
			).Scan(&receiptWindow)
		},
	)
	if err != nil {
		t.Fatalf("read tenant A effective retention receipt: %v", err)
	}
	if receiptWindow != (30 * 24 * time.Hour).String() {
		t.Fatalf("tenant A receipt window = %q, want %q", receiptWindow, (30 * 24 * time.Hour).String())
	}

	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantStale)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(
				ctx,
				`SELECT data->>'retention_window'
				   FROM audit_events
				  WHERE tenant_id = $1 AND action = $2`,
				tenantStale,
				audit.RetentionPruneAction,
			).Scan(&receiptWindow)
		},
	)
	if err != nil {
		t.Fatalf("read stale-policy effective retention receipt: %v", err)
	}
	if receiptWindow != deploymentWindow.String() {
		t.Fatalf(
			"stale-policy receipt window = %q, want deployment clamp %q",
			receiptWindow,
			deploymentWindow.String(),
		)
	}
}

func TestTenantAuditRetentionEffectivePruneWithGlobalKeepForeverPG(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := mkTenant(t, pool, "it-audit-retention-keep-forever-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Errorf("cleanup keep-forever retention tenant: %v", err)
		}
	})

	err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := audit.TenantAppend(
				ctx,
				sc,
				"retention-fixture",
				"retention.old.exported",
				tenantID,
				nil,
			); err != nil {
				return err
			}
			return (store.SIEMDelivery{}).Advance(ctx, sc, 1)
		},
	)
	if err != nil {
		t.Fatalf("seed keep-forever tenant audit: %v", err)
	}
	now := time.Now().UTC()
	if _, err := pool.Exec(
		ctx,
		`UPDATE audit_events SET created_at = $1 WHERE tenant_id = $2`,
		now.Add(-40*24*time.Hour),
		tenantID,
	); err != nil {
		t.Fatalf("backdate keep-forever tenant audit: %v", err)
	}

	engine := New(pool, nil, nil, nil, nil, "", testLog()).
		WithAuditRetentionMaximum(0)
	thirtyDays := 30
	if err := engine.SetRetention(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		RetentionPolicy{
			TenantID:           tenantID,
			AuditRetentionDays: &thirtyDays,
			UpdatedBy:          "tenant-admin",
		},
		"tenant-admin",
	); err != nil {
		t.Fatalf("set finite tenant policy under global keep-forever: %v", err)
	}

	providerWatermarkCalled := false
	runner := audit.NewRetentionRunnerPG(
		pool,
		audit.RetentionPolicy{},
		func(context.Context) (int64, error) {
			providerWatermarkCalled = true
			return 1, nil
		},
		testLog(),
	).WithTenantRetentionWindow(engine.ProviderAuditRetentionWindowFor).
		WithTenantIDsForTest(func(context.Context) ([]string, error) {
			return []string{tenantID}, nil
		}).
		WithNowForTest(func() time.Time { return now })
	summary, err := runner.Tick(ctx)
	if err != nil {
		t.Fatalf("run keep-forever tenant override: %v", err)
	}
	if providerWatermarkCalled {
		t.Fatal("global keep-forever runner consulted provider WORM watermark")
	}
	if summary.ProviderPruned != 0 || summary.TenantPruned != 1 ||
		summary.TenantsChecked != 1 {
		t.Fatalf("keep-forever tenant override summary = %+v, want tenant-only prune", summary)
	}

	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var oldRows int64
			var receiptWindow string
			if err := sc.Q.QueryRow(
				ctx,
				`SELECT count(*) FROM audit_events
				  WHERE tenant_id = $1 AND action = 'retention.old.exported'`,
				tenantID,
			).Scan(&oldRows); err != nil {
				return err
			}
			if oldRows != 0 {
				return fmt.Errorf("keep-forever tenant old rows = %d, want pruned", oldRows)
			}
			if err := sc.Q.QueryRow(
				ctx,
				`SELECT data->>'retention_window'
				   FROM audit_events
				  WHERE tenant_id = $1 AND action = $2`,
				tenantID,
				audit.RetentionPruneAction,
			).Scan(&receiptWindow); err != nil {
				return err
			}
			if receiptWindow != (30 * 24 * time.Hour).String() {
				return fmt.Errorf(
					"keep-forever tenant receipt window = %q, want %q",
					receiptWindow,
					(30 * 24 * time.Hour).String(),
				)
			}
			return audit.TenantVerify(ctx, sc)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
}
