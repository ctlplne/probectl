// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type auditFlowRetentionPruner struct {
	flowstore.Store
	calls []string
	err   error
}

func (p *auditFlowRetentionPruner) DeleteTenantBefore(
	_ context.Context,
	tenantID string,
	_ time.Time,
) error {
	p.calls = append(p.calls, tenantID)
	return p.err
}

type auditSessionRetentionPruner struct {
	calls []string
	err   error
}

func (p *auditSessionRetentionPruner) PruneInactive(
	_ context.Context,
	tenantID string,
	_ time.Duration,
) (int64, error) {
	p.calls = append(p.calls, tenantID)
	return 1, p.err
}

type auditOtelRetentionPruner struct {
	calls []string
}

func (*auditOtelRetentionPruner) EraseTenant(context.Context, string) (int, int, error) {
	return 0, 0, nil
}

func (p *auditOtelRetentionPruner) PruneTenantBefore(
	_ context.Context,
	tenantID string,
	_ time.Time,
) (int, error) {
	p.calls = append(p.calls, tenantID)
	return 1, nil
}

type auditEBPFRetentionPruner struct {
	calls []string
}

func (*auditEBPFRetentionPruner) DeleteTenant(context.Context, string) (int64, error) {
	return 0, nil
}

func (p *auditEBPFRetentionPruner) PruneTenantBefore(
	_ context.Context,
	tenantID string,
	_ time.Time,
) (int, error) {
	p.calls = append(p.calls, tenantID)
	return 1, nil
}

type auditPathRetentionPruner struct {
	calls []string
}

func (*auditPathRetentionPruner) DeleteTenant(context.Context, string) (int, int, error) {
	return 0, 0, nil
}

func (p *auditPathRetentionPruner) PruneTenantBefore(
	_ context.Context,
	tenantID string,
	_ time.Time,
) (int, error) {
	p.calls = append(p.calls, tenantID)
	return 1, nil
}

type auditTopologyRetentionPruner struct {
	calls []string
}

func (*auditTopologyRetentionPruner) DeleteTenant(string) int { return 0 }

func (p *auditTopologyRetentionPruner) PruneTenantBefore(tenantID string, _ time.Time) int {
	p.calls = append(p.calls, tenantID)
	return 1
}

type auditCacheRetentionPruner struct {
	calls []string
}

func (p *auditCacheRetentionPruner) PruneTenantBefore(tenantID string, _ time.Time) int {
	p.calls = append(p.calls, tenantID)
	return 1
}

type auditEndpointEventRetentionPruner struct {
	endpointstore.Store
	calls []string
}

func (p *auditEndpointEventRetentionPruner) PruneTenantBefore(
	_ context.Context,
	tenantID string,
	_ time.Time,
) (int, error) {
	p.calls = append(p.calls, tenantID)
	return 1, nil
}

func TestRetentionAuditIntentFailurePreventsEveryPrune(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-0000000000aa"
	wantErr := errors.New("provider audit unavailable")
	auditedStores := map[string]int{}
	audit := func(ctx context.Context, _, action, target string, data map[string]any) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > retentionAuditTimeout {
			t.Fatalf("retention intent is not bounded: deadline=%v present=%t", deadline, ok)
		}
		if action != "lifecycle.retention_sweep" || target != tenant || data["status"] != "intent" {
			t.Fatalf("retention intent scope = action %q target %q data %+v", action, target, data)
		}
		auditedStores[data["store"].(string)]++
		return wantErr
	}

	flows := &auditFlowRetentionPruner{}
	sessions := &auditSessionRetentionPruner{}
	otel := &auditOtelRetentionPruner{}
	ebpf := &auditEBPFRetentionPruner{}
	paths := &auditPathRetentionPruner{}
	topology := &auditTopologyRetentionPruner{}
	endpoints := &auditCacheRetentionPruner{}
	endpointEvents := &auditEndpointEventRetentionPruner{}
	engine := New(&pgxpool.Pool{}, flows, nil, nil, audit, "", testLog()).
		WithClock(func() time.Time { return t0 }).
		WithSessionRetention(sessions, time.Hour).
		WithOtel(otel).
		WithEBPF(ebpf).
		WithPaths(paths).
		WithTopology(topology).
		WithEndpointRetention(endpoints).
		WithEndpointEvents(endpointEvents).
		WithDerivedIdentityRetentionDays(1)
	policy := retentionSweepPolicy{tenant: tenant, days: map[string]int{
		"flows": 1, "otel": 1, "ebpf": 1, "path": 1, "ai_answers": 1,
	}}

	checks := []struct {
		name string
		run  func() error
	}{
		{"sessions", func() error { return engine.sweepSessionRetention(context.Background(), policy) }},
		{"flows", func() error { return engine.sweepFlowRetention(context.Background(), policy) }},
		{"otel", func() error { return engine.sweepOtelRetention(context.Background(), policy) }},
		{"ebpf", func() error { return engine.sweepEBPFRetention(context.Background(), policy) }},
		{"path", func() error { return engine.sweepPathRetention(context.Background(), policy) }},
		{"ai_answers", func() error { return engine.sweepAIAnswerRetention(context.Background(), policy) }},
		{"derived_caches", func() error { return engine.pruneDerivedIdentityCaches(context.Background(), policy) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); !errors.Is(err, wantErr) {
				t.Fatalf("retention error = %v, want audit failure", err)
			}
		})
	}

	for store, want := range map[string]int{
		"sessions": 1, "flows": 1, "otel": 1, "ebpf": 1, "path": 1,
		"ai_answers": 1, "topology": 1, "endpoint": 1, "endpoint_events": 1,
	} {
		if auditedStores[store] != want {
			t.Errorf("%s intent attempts = %d, want %d", store, auditedStores[store], want)
		}
	}
	if len(auditedStores) != 9 {
		t.Fatalf("audited destructive stores = %+v", auditedStores)
	}
	for store, calls := range map[string][]string{
		"sessions": sessions.calls, "flows": flows.calls, "otel": otel.calls,
		"ebpf": ebpf.calls, "path": paths.calls, "topology": topology.calls,
		"endpoint": endpoints.calls, "endpoint_events": endpointEvents.calls,
	} {
		if len(calls) != 0 {
			t.Errorf("%s pruned after failed intent: %v", store, calls)
		}
	}
}

func TestRetentionAuditIntentFailureIsolatesLaterTenantPrunes(t *testing.T) {
	const (
		tenantA = "00000000-0000-0000-0000-0000000000aa"
		tenantB = "00000000-0000-0000-0000-0000000000bb"
	)
	wantErr := errors.New("tenant A audit unavailable")
	flows := &auditFlowRetentionPruner{}
	sessions := &auditSessionRetentionPruner{}
	var tenantBStatuses []string
	audit := func(_ context.Context, _, _ string, target string, data map[string]any) error {
		if target == tenantA && data["status"] == "intent" {
			return wantErr
		}
		if target == tenantB {
			tenantBStatuses = append(tenantBStatuses, fmt.Sprintf("%s:%s", data["store"], data["status"]))
		}
		return nil
	}
	engine := New(nil, flows, nil, nil, audit, "", testLog()).
		WithSessionRetention(sessions, time.Hour)

	err := engine.sweepRetentionPolicies(context.Background(), []retentionSweepPolicy{
		{tenant: tenantA, days: map[string]int{"flows": 1}},
		{tenant: tenantB, days: map[string]int{"flows": 1}},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("joined sweep error = %v, want tenant A audit error", err)
	}
	if !reflect.DeepEqual(sessions.calls, []string{tenantB}) {
		t.Fatalf("session prunes = %v, want only tenant B", sessions.calls)
	}
	if !reflect.DeepEqual(flows.calls, []string{tenantB}) {
		t.Fatalf("flow prunes = %v, want only tenant B", flows.calls)
	}
	if !reflect.DeepEqual(tenantBStatuses, []string{
		"sessions:intent", "sessions:enforced", "flows:intent", "flows:enforced",
	}) {
		t.Fatalf("tenant B audit protocol = %v", tenantBStatuses)
	}
}

func TestRetentionAuditFailureAfterEverySuccessfulPruneIsReturned(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-0000000000aa"
	policy := retentionSweepPolicy{tenant: tenant, days: map[string]int{
		"flows": 1, "otel": 1, "ebpf": 1, "path": 1, "ai_answers": 1,
	}}
	tests := []struct {
		name  string
		store string
		run   func(*Engine) (int, error)
	}{
		{
			name:  "sessions",
			store: "sessions",
			run: func(engine *Engine) (int, error) {
				pruner := &auditSessionRetentionPruner{}
				engine.WithSessionRetention(pruner, time.Hour)
				err := engine.sweepSessionRetention(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "flows",
			store: "flows",
			run: func(engine *Engine) (int, error) {
				pruner := &auditFlowRetentionPruner{}
				engine.flows = pruner
				err := engine.sweepFlowRetention(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "otel",
			store: "otel",
			run: func(engine *Engine) (int, error) {
				pruner := &auditOtelRetentionPruner{}
				engine.WithOtel(pruner)
				err := engine.sweepOtelRetention(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "ebpf",
			store: "ebpf",
			run: func(engine *Engine) (int, error) {
				pruner := &auditEBPFRetentionPruner{}
				engine.WithEBPF(pruner)
				err := engine.sweepEBPFRetention(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "path",
			store: "path",
			run: func(engine *Engine) (int, error) {
				pruner := &auditPathRetentionPruner{}
				engine.WithPaths(pruner)
				err := engine.sweepPathRetention(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "ai_answers",
			store: "ai_answers",
			run: func(engine *Engine) (int, error) {
				calls := 0
				engine.aiAnswerRetention = func(context.Context, string, time.Duration) (int64, error) {
					calls++
					return 1, nil
				}
				err := engine.sweepAIAnswerRetention(context.Background(), policy)
				return calls, err
			},
		},
		{
			name:  "topology",
			store: "topology",
			run: func(engine *Engine) (int, error) {
				pruner := &auditTopologyRetentionPruner{}
				engine.WithTopology(pruner).WithDerivedIdentityRetentionDays(1)
				err := engine.pruneDerivedIdentityCaches(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "endpoint",
			store: "endpoint",
			run: func(engine *Engine) (int, error) {
				pruner := &auditCacheRetentionPruner{}
				engine.WithEndpointRetention(pruner).WithDerivedIdentityRetentionDays(1)
				err := engine.pruneDerivedIdentityCaches(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
		{
			name:  "endpoint_events",
			store: "endpoint_events",
			run: func(engine *Engine) (int, error) {
				pruner := &auditEndpointEventRetentionPruner{}
				engine.WithEndpointEvents(pruner).WithDerivedIdentityRetentionDays(1)
				err := engine.pruneDerivedIdentityCaches(context.Background(), policy)
				return len(pruner.calls), err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wantErr := errors.New("terminal provider audit unavailable")
			var receipts []map[string]any
			audit := func(ctx context.Context, _, _ string, target string, data map[string]any) error {
				if target != tenant {
					t.Fatalf("audit target = %q, want %q", target, tenant)
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > retentionAuditTimeout {
					t.Fatalf("retention audit is not bounded: deadline=%v present=%t", deadline, ok)
				}
				receipts = append(receipts, data)
				if data["status"] != "intent" {
					return wantErr
				}
				return nil
			}
			engine := New(nil, nil, nil, nil, audit, "", testLog()).
				WithClock(func() time.Time { return t0 })

			calls, err := test.run(engine)
			if !errors.Is(err, wantErr) {
				t.Fatalf("terminal audit error = %v, want %v", err, wantErr)
			}
			if calls != 1 {
				t.Fatalf("successful destructive calls = %d, want 1", calls)
			}
			if len(receipts) != 2 ||
				receipts[0]["store"] != test.store ||
				receipts[0]["status"] != "intent" ||
				receipts[1]["status"] != "enforced" {
				t.Fatalf("audit protocol = %+v", receipts)
			}
			attemptID, ok := receipts[0]["attempt_id"].(string)
			if !ok || attemptID == "" || receipts[1]["attempt_id"] != attemptID {
				t.Fatalf("unpaired audit protocol = %+v", receipts)
			}
		})
	}
}

func TestRetentionAuditFailureReceiptJoinsStoreAndAuditErrors(t *testing.T) {
	const rawStoreError = "clickhouse password=do-not-record unavailable"
	storeErr := errors.New(rawStoreError)
	auditErr := errors.New("provider audit completion unavailable")
	flows := &auditFlowRetentionPruner{err: storeErr}
	var receipts []map[string]any
	audit := func(_ context.Context, _, _ string, _ string, data map[string]any) error {
		receipts = append(receipts, data)
		if data["status"] == "failed" {
			return auditErr
		}
		return nil
	}
	engine := New(nil, flows, nil, nil, audit, "", testLog()).
		WithClock(func() time.Time { return t0 })

	err := engine.sweepFlowRetention(context.Background(), retentionSweepPolicy{
		tenant: "00000000-0000-0000-0000-0000000000aa",
		days:   map[string]int{"flows": 1},
	})
	if !errors.Is(err, storeErr) || !errors.Is(err, auditErr) {
		t.Fatalf("retention error = %v, want joined store and audit failures", err)
	}
	if len(receipts) != 2 || receipts[0]["status"] != "intent" || receipts[1]["status"] != "failed" {
		t.Fatalf("failure audit protocol = %+v", receipts)
	}
	if strings.Contains(fmt.Sprint(receipts[1]), rawStoreError) {
		t.Fatalf("failure receipt leaked dependency details: %+v", receipts[1])
	}
	if receipts[1]["failure"] != "store_prune_failed" {
		t.Fatalf("failure receipt = %+v", receipts[1])
	}
	if receipts[0]["attempt_id"] == "" || receipts[1]["attempt_id"] != receipts[0]["attempt_id"] {
		t.Fatalf("unpaired failure receipt = %+v", receipts)
	}
	if receipts[1]["deleted_count_known"] != false {
		t.Fatalf("failed prune overclaimed a deletion count: %+v", receipts[1])
	}
}

func TestRetentionDelegatedObjectReceiptDoesNotClaimInProcessPruneIntent(t *testing.T) {
	const tenant = "00000000-0000-0000-0000-0000000000aa"
	ctx := context.Background()
	objects := objectstore.NewMemory()
	key := objectstore.TenantKey(tenant, "browser", "retained.png")
	if err := objects.Put(ctx, key, "image/png", []byte("still externally governed")); err != nil {
		t.Fatal(err)
	}
	var receipts []map[string]any
	engine := New(nil, nil, objects, nil,
		func(_ context.Context, _, _ string, target string, data map[string]any) error {
			if target != tenant {
				t.Fatalf("delegated receipt target = %q, want %q", target, tenant)
			}
			receipts = append(receipts, data)
			return nil
		},
		"", testLog(),
	).WithClock(func() time.Time { return t0 })

	err := engine.receiptDelegatedRetention(ctx, retentionSweepPolicy{
		tenant: tenant,
		days:   map[string]int{"objects": 7},
	}, "objects", "object_store_lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 1 ||
		receipts[0]["status"] != "delegated" ||
		receipts[0]["source"] != "object_store_lifecycle" ||
		receipts[0]["attempt_id"] != nil {
		t.Fatalf("object lifecycle receipt overclaimed an in-process attempt: %+v", receipts)
	}
	keys, err := objects.List(ctx, objectstore.TenantKey(tenant)+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(keys, []string{key}) {
		t.Fatalf("delegated receipt mutated object store: keys=%v", keys)
	}
}
