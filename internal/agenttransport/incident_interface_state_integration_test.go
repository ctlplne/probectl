// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type interfaceStateTestAuthorizer = func(context.Context, entity.ContextRecord, store.IncidentImpactEntity) error

func proveIncidentInterfaceStateReaders(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant, contextID, routerID string, client *agent.EvidenceClient, original entity.Observation) ([]store.IncidentInterfaceStateSource, []store.IncidentInterfaceStateMeasurement, interfaceStateTestAuthorizer) {
	t.Helper()
	// A later unavailable point must survive the complete read. It cannot
	// inherit an earlier state merely because the identity is unchanged.
	missing := original
	missing.ID, missing.ObservedAt, missing.SNMPInterfaceState = newUUID(t), time.Now().UTC().Truncate(time.Microsecond), nil
	if accepted, unresolved, err := client.Submit(ctx, []entity.Observation{missing}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("unavailable-state point was not retained", accepted, unresolved, err)
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	var interfaceID string
	if err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM entity_evidence WHERE tenant_id=$1 AND observation_id=$2`, tenant, original.ID).Scan(&interfaceID)
	}); err != nil {
		t.Fatal(err)
	}
	authorize := func(_ context.Context, record entity.ContextRecord, member store.IncidentImpactEntity) error {
		if record.TenantID != tenant || record.ContextID != contextID || member.ContextID != contextID || member.EntityID != routerID && member.EntityID != interfaceID {
			return entity.ErrScopeMismatch
		}
		return nil
	}
	var sources []store.IncidentInterfaceStateSource
	var reads []store.IncidentInterfaceStateMeasurement
	if err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var generation int64
		if err := sc.Q.QueryRow(ctx, `SELECT COALESCE((SELECT generation FROM flow_snapshot_epochs WHERE tenant_id=$1),1)`, tenant).Scan(&generation); err != nil {
			return err
		}
		inputs := &store.IncidentImpactInputs{TenantID: tenant, SourceGeneration: generation, Entities: []store.IncidentImpactEntity{{ContextID: contextID, EntityID: routerID, IncidentRoot: true}}}
		var err error
		sources, err = (store.Incidents{}).InterfaceStateSourcesInScope(ctx, sc, inputs, entity.InterfaceRolePolicyBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}, authorize)
		if err != nil {
			return err
		}
		if len(sources) != 1 || !sources[0].Current || sources[0].TenantID != tenant || sources[0].ContextID != contextID || sources[0].EntityID != interfaceID || sources[0].RouterID != routerID || sources[0].AgentID != original.Source.AgentID || sources[0].IfIndex != 7 {
			return fmt.Errorf("complete current interface cohort lost its canonical source: %d", len(sources))
		}
		reads, err = (store.Incidents{}).InterfaceStateMeasurementsInScope(ctx, sc, sources, original.ObservedAt.Add(-time.Minute), time.Now().UTC(), 1<<20, authorize)
		if err != nil {
			return err
		}
		if len(reads) != 2 {
			return fmt.Errorf("complete original state and unavailable point changed: %d", len(reads))
		}
		available, unavailable := 0, 0
		for _, read := range reads {
			if read.TenantID != tenant || read.ContextID != contextID || read.EntityID != interfaceID || read.AgentID != original.Source.AgentID || read.EvidenceID == "" || read.CaptureDigest == ([32]byte{}) {
				return errors.New("interface state receipt crossed tenant/source scope")
			}
			if read.ObservationID == original.ID && read.Available && read.State != nil && *read.State.OperStatus == *original.SNMPInterfaceState.OperStatus && *read.State.AdminStatus == *original.SNMPInterfaceState.AdminStatus {
				available++
			} else if read.ObservationID == missing.ID && !read.Available && read.State == nil {
				unavailable++
			} else {
				return errors.New("state history invented a value, omitted a gap or borrowed a sibling")
			}
		}
		if available != 1 || unavailable != 1 {
			return errors.New("state coverage filled a missing observation")
		}
		return (store.Incidents{}).RecheckInterfaceStateMeasurementsInScope(ctx, sc, sources, reads, 1<<20, authorize)
	}); err != nil {
		t.Fatal("original mTLS interface-state current reader", err)
	}
	if err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		denied := func(context.Context, entity.ContextRecord, store.IncidentImpactEntity) error {
			return entity.ErrScopeMismatch
		}
		got, err := (store.Incidents{}).InterfaceStateMeasurementsInScope(ctx, sc, sources, original.ObservedAt.Add(-time.Minute), time.Now().UTC(), 1<<20, denied)
		if !errors.Is(err, entity.ErrScopeMismatch) || got != nil {
			return errors.New("captured source bypassed current per-resource authorization")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		for _, mutate := range []func(*store.IncidentInterfaceStateMeasurement){
			func(r *store.IncidentInterfaceStateMeasurement) { r.EntityID = routerID },
			func(r *store.IncidentInterfaceStateMeasurement) { r.AgentID = "other-agent" },
			func(r *store.IncidentInterfaceStateMeasurement) { r.ConfiguredRef = "192.0.2.8" },
		} {
			changed := append([]store.IncidentInterfaceStateMeasurement(nil), reads...)
			mutate(&changed[0])
			if err := (store.Incidents{}).RecheckInterfaceStateMeasurementsInScope(ctx, sc, sources, changed, 1<<20, authorize); !errors.Is(err, entity.ErrScopeMismatch) {
				return fmt.Errorf("original selector borrowed another source's read grant: %v", err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET snmp_interface_state=jsonb_set(snmp_interface_state,'{oper_status}','7'::jsonb) WHERE tenant_id=$1 AND observation_id=$2`, tenant, original.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		err := (store.Incidents{}).RecheckInterfaceStateMeasurementsInScope(ctx, sc, sources, reads, 1<<20, authorize)
		if !errors.Is(err, entity.ErrConflictingEvidence) {
			return fmt.Errorf("changed original body survived publication: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(original.SNMPInterfaceState)
	if err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET snmp_interface_state=$3::jsonb WHERE tenant_id=$1 AND observation_id=$2`, tenant, original.ID, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return sources, reads, authorize
}

func proveIncidentInterfaceStateRevocation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenant string, sources []store.IncidentInterfaceStateSource, reads []store.IncidentInterfaceStateMeasurement, authorize interfaceStateTestAuthorizer) {
	t.Helper()
	if err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		err := (store.Incidents{}).RecheckInterfaceStateMeasurementsInScope(ctx, sc, sources, reads, 1<<20, authorize)
		if !errors.Is(err, sourceepoch.ErrInvalidating) {
			return fmt.Errorf("withdrawn current certificate retained a state reader grant: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
