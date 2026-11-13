// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestBMPPeerSessionRealMTLSKeepsOriginalFrameTenantAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)) })
	area, router, observationID := newUUID(t), newUUID(t), newUUID(t)
	lanes := []icmpWireLane{seedICMPWireLane(ctx, t, pool, server, area, router), seedICMPWireLane(ctx, t, pool, server, area, router)}
	const origin = "same-physical-router"
	serials := map[string]string{}
	claims := map[string]entity.Observation{}
	raw := make([]byte, 49)
	raw[0], raw[5], raw[48] = 3, 2, 4
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[28:32], []byte{192, 0, 2, 7})
	binary.BigEndian.PutUint32(raw[32:36], 4294967295)
	for _, lane := range lanes {
		cert, _, err := server.ca.IssueClientCert(origin, crypto.BMPSPIFFEID(lane.tenant, origin), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(cert)
		if block == nil {
			t.Fatal("router certificate missing")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		serials[lane.tenant] = leaf.SerialNumber.Text(16)
		if err := store.NewAgentIdentities(pool).Record(ctx, lane.tenant, origin, crypto.BMPSPIFFEID(lane.tenant, origin), serials[lane.tenant], leaf.NotAfter, ""); err != nil {
			t.Fatal(err)
		}
		bound := tenancy.WithTenant(ctx, tenancy.ID(lane.tenant))
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			return store.NewEntityRegistry(pool).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: lane.sender, Kind: entity.BMPPeer, SourceRef: origin}, area, router)
		}); err != nil {
			t.Fatal(err)
		}
		fact, err := bgp.DecodePhysicalPeerSession(ctx, raw, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		claim := entity.Observation{ID: observationID, Source: entity.SourceKey{AgentID: lane.sender, Kind: entity.BMPPeer, SourceRef: origin}, Alias: entity.AliasKey{Kind: entity.BMPPeerAlias, Value: "192.0.2.7/as4294967295"}, SourceRef: "bmp:router:" + origin + ":peer-asn:4294967295", OriginSerial: serials[lane.tenant], ObservedAt: time.Now().UTC().Truncate(time.Microsecond), BMPPeerSession: fact}
		claims[lane.tenant] = claim
		for range 2 {
			if accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{claim}); err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("real mTLS typed retention or replay refused", accepted, unresolved, err)
			}
		}
	}
	for _, lane := range lanes {
		bound := tenancy.WithTenant(ctx, tenancy.ID(lane.tenant))
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var owner, contextID, entityID, sender, serial, originSerial string
			var body []byte
			if err := sc.Q.QueryRow(ctx, `SELECT tenant_id::text,context_id::text,entity_id::text,agent_id,sender_serial,origin_serial,bmp_peer_session FROM entity_evidence WHERE observation_id=$1`, observationID).Scan(&owner, &contextID, &entityID, &sender, &serial, &originSerial, &body); err != nil {
				return err
			}
			var fact entity.BMPPeerSession
			if err := json.Unmarshal(body, &fact); err != nil {
				return err
			}
			if owner != lane.tenant || contextID != area || entityID != router || sender != lane.sender || serial != lane.serial || originSerial != serials[lane.tenant] || fact.State != "down" || !bytes.Equal(fact.RawFrame, raw) {
				return fmt.Errorf("mTLS tenant, origin or original bytes changed")
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence`).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("replay or sibling tenant entered RLS history: %d", count)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	a, b := lanes[0], lanes[1]
	forged := claims[a.tenant]
	forged.ID = newUUID(t)
	forged.OriginSerial = serials[b.tenant]
	if accepted, unresolved, err := a.client.Submit(ctx, []entity.Observation{forged}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("foreign origin became tenant authority", accepted, unresolved, err)
	}
	changed := append([]byte(nil), raw...)
	changed[48] = 5
	fact, err := bgp.DecodePhysicalPeerSession(ctx, changed, bgp.PeerMessageBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	conflict := claims[a.tenant]
	conflict.BMPPeerSession = fact
	if _, _, err := a.client.Submit(ctx, []entity.Observation{conflict}); status.Code(err) != codes.AlreadyExists {
		t.Fatal("same UUID changed stored session metadata", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='operator' WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`, a.tenant, origin, serials[a.tenant])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, lane := range lanes {
		claim := claims[lane.tenant]
		claim.ID = newUUID(t)
		accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{claim})
		want := 1
		if lane.tenant == a.tenant {
			want = 0
		}
		if err != nil || accepted != want || unresolved != 1-want {
			t.Fatal("router revocation crossed tenant boundary or was ignored", accepted, unresolved, err)
		}
	}
	t.Log("real-integration: actual issued evidence mTLS and pooled RLS retain original whole BMP bytes, exact router serials, typed acknowledgments, immutable replay and tenant-isolated revocation; source frame is modeled, actual router/listener and four domain labs remain separate")
}
