// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual client/listener/mTLS/Postgres. Inputs are simulated complete SNMP
// tables; this does not replace the same-router FRR/SNMP or release proof.
func TestSNMPPrefixRealMTLSKeepsTenantSenderReplayAndCompleteMetadata(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool)
	contextID, routerID, observationID, stateObservationID := newUUID(t), newUUID(t), newUUID(t), newUUID(t)
	for index, suffix := range []string{"a", "b"} {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("prefix-wire-%s-%d", suffix, time.Now().UnixNano()), suffix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		agentID := newUUID(t)
		var cert, key []byte
		for _, uri := range []string{crypto.AgentSPIFFEID(tenant.ID, agentID), crypto.EntitySPIFFEID(tenant.ID, agentID)} {
			cert, key, err = server.ca.IssueClientCert(agentID, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("QA certificate missing")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, agentID, uri, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agentID, "prefix-agent", "192.0.2.99", "fixture", crypto.AgentSPIFFEID(tenant.ID, agentID), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','same-vrf')`, tenant.ID, contextID, newUUID(t), newUUID(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same-router')`, tenant.ID, contextID, routerID); err != nil {
				return err
			}
			return store.NewEntityRegistry(pool).AssignEntitySource(ctx, sc,
				entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, contextID, routerID)
		}); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		client, err := agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "evidence.crt", cert), writeTemp(t, dir, "evidence.key", key), server.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		prefix := []string{"198.51.100.0/24", "203.0.113.0/24"}[index]
		claim := entity.Observation{ID: observationID, Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"},
			Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
			SNMPInterfacePrefixes: []entity.SNMPInterfacePrefix{{IfIndex: 7, Prefix: netip.MustParsePrefix(prefix), OnLink: true}, {IfIndex: 9, Prefix: netip.MustParsePrefix("2001:db8::/32")}}}
		for range 2 {
			accepted, unresolved, err := client.Submit(ctx, []entity.Observation{claim})
			if err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("complete prefix mTLS evidence or exact replay refused", accepted, unresolved, err)
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			rows, err := sc.Q.Query(ctx, `SELECT context_id::text,entity_id::text,snmp_interface_prefixes,observed_at FROM entity_evidence WHERE observation_id=$1`, observationID)
			if err != nil {
				return err
			}
			defer rows.Close()
			count := 0
			for rows.Next() {
				var context, router string
				var body []byte
				var at time.Time
				if err := rows.Scan(&context, &router, &body, &at); err != nil {
					return err
				}
				var got []entity.SNMPInterfacePrefix
				if err := json.Unmarshal(body, &got); err != nil {
					return err
				}
				if context != contextID || router != routerID || !at.Equal(claim.ObservedAt) || !slices.Equal(got, claim.SNMPInterfacePrefixes) {
					t.Fatal("complete prefix evidence changed sender-selected scope, bytes or replay clock")
				}
				count++
			}
			if count != 1 {
				t.Fatal("equal-id prefix evidence crossed FORCE-RLS or duplicated a replay", count)
			}
			return rows.Err()
		}); err != nil {
			t.Fatal(err)
		}
		oper, admin := uint32(index+1), uint32(1)
		stateClaim := entity.Observation{ID: stateObservationID, Source: claim.Source,
			Alias: entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
			SNMPInterfaceState: &entity.SNMPInterfaceState{Version: 1, OperStatus: &oper, AdminStatus: &admin}}
		for range 2 {
			if accepted, unresolved, err := client.Submit(ctx, []entity.Observation{stateClaim}); err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("typed interface state or immutable replay was not retained", accepted, unresolved, err)
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var body []byte
			var gotContext, parent, sender, serial string
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence WHERE observation_id=$1 AND snmp_interface_state IS NOT NULL`, stateObservationID).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("typed state duplicated or crossed tenant RLS: %d", count)
			}
			if err := sc.Q.QueryRow(ctx, `SELECT e.context_id::text,n.parent_entity_id::text,e.agent_id,e.sender_serial,e.snmp_interface_state
 FROM entity_evidence e JOIN entities n ON (n.tenant_id,n.context_id,n.id)=(e.tenant_id,e.context_id,e.entity_id)
 WHERE e.observation_id=$1`, stateObservationID).Scan(&gotContext, &parent, &sender, &serial, &body); err != nil {
				return err
			}
			var got entity.SNMPInterfaceState
			if err := json.Unmarshal(body, &got); err != nil {
				return err
			}
			if gotContext != contextID || parent != routerID || sender != agentID || serial == "" || !reflect.DeepEqual(&got, stateClaim.SNMPInterfaceState) {
				return fmt.Errorf("state receipt lost current source, canonical parent or original enum")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		changedState := stateClaim
		changedBody := *stateClaim.SNMPInterfaceState
		changedOper := uint32(7)
		changedBody.OperStatus = &changedOper
		changedState.SNMPInterfaceState = &changedBody
		if _, _, err := client.Submit(ctx, []entity.Observation{changedState}); status.Code(err) != codes.AlreadyExists {
			t.Fatal("same UUID rewrote original interface state", err)
		}
		if accepted, unresolved, err := client.Submit(ctx, []entity.Observation{stateClaim}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("refused mutation changed the retained original state", accepted, unresolved, err)
		}
		unownedState := stateClaim
		unownedState.ID, unownedState.Source.SourceRef = newUUID(t), "192.0.2.8"
		if accepted, unresolved, err := client.Submit(ctx, []entity.Observation{unownedState}); err != nil || accepted != 0 || unresolved != 1 {
			t.Fatal("unassigned source gained canonical interface state", accepted, unresolved, err)
		}
		unowned := claim
		unowned.ID = newUUID(t)
		unowned.Source.SourceRef = "192.0.2.8"
		accepted, unresolved, err := client.Submit(ctx, []entity.Observation{unowned})
		if err != nil || accepted != 0 || unresolved != 1 {
			t.Fatal("unassigned configured target gained canonical prefix authority", accepted, unresolved, err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM agent_identities WHERE tenant_id=$1 AND agent_id=$2 AND spiffe_id=$3`, tenant.ID, agentID, crypto.EntitySPIFFEID(tenant.ID, agentID)); err != nil {
			t.Fatal(err)
		}
		claim.ID = newUUID(t)
		if _, _, err := client.Submit(ctx, []entity.Observation{claim}); status.Code(err) != codes.Unauthenticated {
			t.Fatal("revoked exact evidence credential republished prefix metadata", err)
		}
		stateClaim.ID = newUUID(t)
		if _, _, err := client.Submit(ctx, []entity.Observation{stateClaim}); status.Code(err) != codes.Unauthenticated {
			t.Fatal("revoked exact evidence credential republished interface state", err)
		}
	}
}
