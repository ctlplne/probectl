// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestSNMPPhysicalInventoryEvidenceKeepsExactTenantAndPollEpoch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool)
	contextID, siteID, deviceID := newUUID(t), newUUID(t), newUUID(t)
	const target = "192.0.2.12"
	registry := store.NewEntityRegistry(pool)
	var tenants [2]string
	var sources [2]entity.SourceKey
	var clients [2]*agent.EvidenceClient
	for lane := range tenants {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("physical-wire-%d-%d", lane, time.Now().UnixNano()), "inventory")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		tenants[lane] = tenant.ID
		// Agent IDs are globally unique. Keep the target, context and device
		// overlapping across tenants while issuing distinct enrolled agents.
		source := entity.SourceKey{AgentID: newUUID(t), Kind: entity.DeviceTarget, SourceRef: target}
		sources[lane] = source
		agentURI := crypto.AgentSPIFFEID(tenant.ID, source.AgentID)
		evidenceURI := crypto.EntitySPIFFEID(tenant.ID, source.AgentID)
		var cert, key []byte
		for _, uri := range []string{agentURI, evidenceURI} {
			cert, key, err = server.ca.IssueClientCert(source.AgentID, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("the test certificate was absent")
			}
			leaf, err := crypto.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, source.AgentID, uri, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
		err = tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, source.AgentID, "physical-wire", target, "fixture", agentURI, nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant.ID, contextID, siteID, newUUID(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label)
VALUES ($1,$2,$3,'device','overlap')`, tenant.ID, contextID, deviceID); err != nil {
				return err
			}
			return registry.AssignEntitySource(ctx, sc, source, contextID, deviceID)
		})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		client, err := agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "inventory.crt", cert), writeTemp(t, dir, "inventory.key", key), server.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		clients[lane] = client
	}

	read := func(bound, selected string, source entity.SourceKey) (store.DevicePhysicalInventoryEvidence, error) {
		var evidence store.DevicePhysicalInventoryEvidence
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(bound)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			evidence, err = registry.CurrentDevicePhysicalInventoryInScope(ctx, sc, entity.Scope{TenantID: selected, ContextID: contextID}, deviceID, source)
			return err
		})
		return evidence, err
	}
	original := func(tenant, evidenceID string) string {
		t.Helper()
		var observationID string
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT observation_id::text FROM entity_evidence WHERE tenant_id=$1 AND id=$2`,
				tenant, evidenceID).Scan(&observationID)
		}); err != nil {
			t.Fatal("inventory evidence does not identify an owned observation", err)
		}
		return observationID
	}
	send := func(lane int, claim entity.Observation) error {
		accepted, unresolved, err := clients[lane].Submit(ctx, []entity.Observation{claim})
		if err == nil && (accepted != 1 || unresolved != 0) {
			t.Fatalf("the original device was unresolved %d/%d", accepted, unresolved)
		}
		return err
	}
	observationClock := func() time.Time {
		t.Helper()
		var at time.Time
		if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at.UTC()
	}
	parent := uint32(0)
	claim := entity.Observation{ID: newUUID(t), Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: target},
		SourceRef: entity.SNMPPhysicalInventorySource, ObservedAt: observationClock()}
	for lane, tenant := range tenants {
		inventory := entity.SNMPPhysicalInventory{Version: 1, Available: true, Components: []entity.SNMPPhysicalComponent{
			{Index: 2, Class: 3, Parent: &parent, Model: "same-chassis", Firmware: fmt.Sprintf("release-%d", lane)},
			{Index: 9, Class: 9, Model: "same-module", Firmware: fmt.Sprintf("module-%d", lane)},
		}}
		claim.Source, claim.SNMPPhysicalInventory = sources[lane], &inventory
		if err := send(lane, claim); err != nil {
			t.Fatal(err)
		}
		got, err := read(tenant, tenant, sources[lane])
		if err != nil || got.EvidenceID == claim.ID || original(tenant, got.EvidenceID) != claim.ID ||
			!got.ObservedAt.Equal(claim.ObservedAt) || !got.Snapshot.Available || len(got.Snapshot.Components) != 2 ||
			got.Snapshot.Components[0].Firmware != inventory.Components[0].Firmware ||
			got.Snapshot.Components[0].Parent == nil || *got.Snapshot.Components[0].Parent != 0 ||
			got.Snapshot.Components[1].Parent != nil {
			t.Fatal("the original clock, hardware evidence or parent presence was lost", err)
		}
		if err := send(lane, claim); err != nil {
			t.Fatal("a byte-identical retry changed the original observation", err)
		}
		inventory.Components[0].Firmware = "changed-after-original"
		if err := send(lane, claim); status.Code(err) != codes.AlreadyExists {
			t.Fatal("the same source and observation ID accepted different firmware", err)
		}
	}
	if _, err := read(tenants[0], tenants[1], sources[1]); !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatal("the datastore accepted a sibling inventory scope", err)
	}
	if _, err := read(tenants[0], tenants[0], sources[1]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("a sibling collector resolved under the local tenant", err)
	}
	// Different authorized statements at one clock are ambiguous for the
	// source. A completed later poll still establishes its own epoch.
	claim.Source = sources[0]
	ambiguous := claim
	ambiguous.ID = newUUID(t)
	ambiguous.SNMPPhysicalInventory = &entity.SNMPPhysicalInventory{Version: 1, Available: true,
		Components: []entity.SNMPPhysicalComponent{{Index: 2, Class: 3, Firmware: "conflicting-original"}}}
	if err := send(0, ambiguous); err != nil {
		t.Fatal(err)
	}
	if _, err := read(tenants[0], tenants[0], sources[0]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("a conflicting same-clock measurement was presented as current", err)
	}
	claim.ID, claim.ObservedAt = newUUID(t), observationClock()
	claim.SNMPPhysicalInventory = &entity.SNMPPhysicalInventory{Version: 1}
	if err := send(0, claim); err != nil {
		t.Fatal(err)
	}
	left, err := read(tenants[0], tenants[0], sources[0])
	if err != nil || left.EvidenceID == claim.ID || original(tenants[0], left.EvidenceID) != claim.ID ||
		left.Snapshot.Available || len(left.Snapshot.Components) != 0 {
		t.Fatal("an unavailable newest poll resurrected old values", err)
	}
	right, err := read(tenants[1], tenants[1], sources[1])
	if err != nil || len(right.Snapshot.Components) != 2 || right.Snapshot.Components[0].Firmware != "release-1" {
		t.Fatal("an overlapping peer update changed the sibling's inventory", err)
	}
	if _, _, err := store.NewAgentIdentities(pool).RevokeAgent(ctx, tenants[0], sources[0].AgentID, "inventory-test"); err != nil {
		t.Fatal(err)
	}
	if _, err := read(tenants[0], tenants[0], sources[0]); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("a revoked device source retained current inventory authority", err)
	}
}
