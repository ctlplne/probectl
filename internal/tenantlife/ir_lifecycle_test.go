// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenantlife

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type irLifecycleFake struct {
	events             *[]string
	planID             string
	planErr            error
	executeErr         error
	failureErr         error
	keys               map[string]bool
	executedTenants    []string
	failureTenant      string
	failureActor       string
	failurePlanID      string
	failureClass       string
	failureContextErr  error
	failureHasDeadline bool
}

func successfulIntegrationIRLifecycle() *irLifecycleFake {
	events := []string{}
	return &irLifecycleFake{events: &events, planID: "integration-ir-shred-plan"}
}

func (f *irLifecycleFake) Plan(_ context.Context, tenantID, _ string) (string, error) {
	*f.events = append(*f.events, "plan:"+tenantID)
	return f.planID, f.planErr
}

func (f *irLifecycleFake) Execute(_ context.Context, tenantID, _ string, _ string) error {
	*f.events = append(*f.events, "execute:"+tenantID)
	f.executedTenants = append(f.executedTenants, tenantID)
	if f.executeErr == nil && f.keys != nil {
		delete(f.keys, tenantID)
	}
	return f.executeErr
}

func (f *irLifecycleFake) RecordFailure(
	ctx context.Context,
	tenantID, actor, planID, failure string,
) error {
	*f.events = append(*f.events, "failure:"+tenantID)
	f.failureTenant = tenantID
	f.failureActor = actor
	f.failurePlanID = planID
	f.failureClass = failure
	f.failureContextErr = ctx.Err()
	_, f.failureHasDeadline = ctx.Deadline()
	return f.failureErr
}

type irLifecycleFlowStore struct {
	flowstore.Store
	events    *[]string
	deleteErr error
	onDelete  func()
	rows      map[string]bool
}

func (s *irLifecycleFlowStore) DeleteTenant(_ context.Context, tenantID string) (int64, error) {
	*s.events = append(*s.events, "store:"+tenantID)
	if s.onDelete != nil {
		s.onDelete()
	}
	if s.deleteErr != nil {
		return 0, s.deleteErr
	}
	delete(s.rows, tenantID)
	return 0, nil
}

func TestIRCryptoShredPlanFailurePreventsDestructiveCalls(t *testing.T) {
	events := []string{}
	flows := &irLifecycleFlowStore{
		Store:  flowstore.NewMemory(),
		events: &events,
		rows:   map[string]bool{"tenant-a": true},
	}
	lifecycle := &irLifecycleFake{
		events:  &events,
		planID:  "plan-a",
		planErr: errors.New("coverage incomplete"),
		keys:    map[string]bool{"tenant-a": true},
	}
	engine := New(nil, flows, nil, nil, nil, "test backups", testLog()).
		WithIRAttributionLifecycle(lifecycle)

	if _, err := engine.Erase(context.Background(), "tenant-a", "a", "investigator"); err == nil {
		t.Fatal("Erase must fail when IR lifecycle planning fails")
	}
	if want := []string{"plan:tenant-a"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("calls after plan failure = %v, want %v", events, want)
	}
	if !flows.rows["tenant-a"] {
		t.Fatal("plan failure deleted tenant store data")
	}
	if !lifecycle.keys["tenant-a"] {
		t.Fatal("plan failure destroyed the tenant IR key")
	}
}

func TestIRCryptoShredStoreFailureRecordsBoundedFailureWithoutExecute(t *testing.T) {
	events := []string{}
	ctx, cancel := context.WithCancel(context.Background())
	flows := &irLifecycleFlowStore{
		Store:     flowstore.NewMemory(),
		events:    &events,
		deleteErr: errors.New("flow deletion unavailable"),
		onDelete:  cancel,
		rows:      map[string]bool{"tenant-a": true},
	}
	lifecycle := &irLifecycleFake{
		events: &events,
		planID: "plan-a",
		keys:   map[string]bool{"tenant-a": true},
	}
	engine := New(nil, flows, nil, nil, nil, "test backups", testLog()).
		WithIRAttributionLifecycle(lifecycle)

	att, err := engine.Erase(ctx, "tenant-a", "a", "investigator")
	if err != nil {
		t.Fatalf("Erase returned unexpected receipt error: %v", err)
	}
	if att.Complete {
		t.Fatal("store failure produced a complete attestation")
	}
	want := []string{"plan:tenant-a", "store:tenant-a", "failure:tenant-a"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("call order = %v, want %v", events, want)
	}
	if lifecycle.failureContextErr != nil {
		t.Fatalf("failure receipt inherited canceled context: %v", lifecycle.failureContextErr)
	}
	if !lifecycle.failureHasDeadline {
		t.Fatal("failure receipt context has no finite deadline")
	}
	if lifecycle.failureTenant != "tenant-a" ||
		lifecycle.failureActor != "investigator" ||
		lifecycle.failurePlanID != "plan-a" ||
		lifecycle.failureClass != "store_erasure_incomplete" {
		t.Fatalf("failure receipt was not correlated: %+v", lifecycle)
	}
	if len(lifecycle.executedTenants) != 0 {
		t.Fatalf("IR crypto-shred executed after store failure: %v", lifecycle.executedTenants)
	}
	if !lifecycle.keys["tenant-a"] {
		t.Fatal("store failure destroyed the tenant IR key")
	}
}

func TestIRCryptoShredSuccessOrdersAndScopesTwoTenants(t *testing.T) {
	events := []string{}
	flows := &irLifecycleFlowStore{
		Store:  flowstore.NewMemory(),
		events: &events,
		rows:   map[string]bool{"tenant-a": true, "tenant-b": true},
	}
	lifecycle := &irLifecycleFake{
		events: &events,
		planID: "plan-a",
		keys:   map[string]bool{"tenant-a": true, "tenant-b": true},
	}
	engine := New(nil, flows, nil, nil, nil, "test backups", testLog()).
		WithIRAttributionLifecycle(lifecycle)

	att, err := engine.Erase(context.Background(), "tenant-a", "a", "investigator")
	if err != nil {
		t.Fatalf("Erase: %v", err)
	}
	if !att.Complete {
		t.Fatalf("attestation incomplete: %+v", att.Stores)
	}
	want := []string{"plan:tenant-a", "store:tenant-a", "execute:tenant-a"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("call order = %v, want %v", events, want)
	}
	if flows.rows["tenant-a"] || lifecycle.keys["tenant-a"] {
		t.Fatal("tenant A data or IR key survived successful erase")
	}
	if !flows.rows["tenant-b"] || !lifecycle.keys["tenant-b"] {
		t.Fatal("tenant A erase changed tenant B state")
	}
}

func TestIRDeletionRetainsAttributionTablesFromGenericPostgresErase(t *testing.T) {
	got := appRoleEraseTables([]string{
		"ordinary_tenant_rows",
		"audit_events",
		"audit_subject_erasures",
		"ir_attribution_records",
		"ir_attribution_heads",
	})
	want := []string{"ordinary_tenant_rows"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("generic Postgres erase tables = %v, want %v", got, want)
	}
}
