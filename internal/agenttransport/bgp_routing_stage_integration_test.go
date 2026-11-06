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
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func routingPeerUpWire(t *testing.T) []byte {
	t.Helper()
	open := make([]byte, 29)
	for i := range 16 {
		open[i] = 255
	}
	open[18], open[19] = 1, 4
	binary.BigEndian.PutUint16(open[20:22], 64512)
	binary.BigEndian.PutUint16(open[22:24], 180)
	copy(open[24:28], []byte{192, 0, 2, 1})
	options := []byte{2, 12, 65, 4, 0, 0, 252, 0, 1, 4, 0, 2, 0, 1}
	open[28] = byte(len(options))
	open = append(open, options...)
	binary.BigEndian.PutUint16(open[16:18], uint16(len(open)))
	raw := make([]byte, 68)
	raw[0], raw[5], raw[6] = 3, 3, 3
	binary.BigEndian.PutUint32(raw[32:36], 64512)
	copy(raw[36:40], []byte{192, 0, 2, 1})
	raw = append(raw, open...)
	raw = append(raw, open...)
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	return raw
}

// Actual served mTLS evidence client/listener and application-role Postgres.
// BGP bytes are a protocol fixture, not a real-router or flow-join receipt.
func TestRoutingStagingRealMTLSKeepsTenantOriginRetryAndPrivateState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ts := startTestServer(ctx, t, pool)
	contextID, siteID, routerID, originID, nonce := newUUID(t), newUUID(t), newUUID(t), newUUID(t), newUUID(t)
	type lane struct {
		tenant, collector, originSerial string
		client                          *agent.EvidenceClient
		input                           *agentv1.BmpRoutingPeerUp
		receipt                         *agentv1.BmpRoutingStagingReceipt
	}
	var lanes []lane
	for _, suffix := range []string{"a", "b"} {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("routing-stage-%s-%d", suffix, time.Now().UnixNano()), suffix)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		collector := newUUID(t)
		var cert, key []byte
		var originSerial string
		for _, plane := range []string{"agent", "entity", "bmp"} {
			who := collector
			uri := crypto.AgentSPIFFEID(tenant.ID, collector)
			if plane == "entity" {
				uri = crypto.EntitySPIFFEID(tenant.ID, collector)
			}
			if plane == "bmp" {
				who = originID
				uri = crypto.BMPSPIFFEID(tenant.ID, originID)
			}
			c, k, err := ts.ca.IssueClientCert(who, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(c)
			if block == nil {
				t.Fatal("QA certificate missing")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, who, uri, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
			if plane == "entity" {
				cert, key = c, k
			}
			if plane == "bmp" {
				originSerial = leaf.SerialNumber.Text(16)
			}
		}
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
		if err := tenancy.InTenant(tenantCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, collector, "routing-wire", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant.ID, collector), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','same-vrf')`, tenant.ID, contextID, siteID, newUUID(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'site','site'),($1,$2,$4,'device','router')`, tenant.ID, contextID, siteID, routerID); err != nil {
				return err
			}
			return store.NewEntityRegistry(pool).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: collector, Kind: entity.BMPPeer, SourceRef: originID}, contextID, routerID)
		}); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		client, err := agent.DialEntityEvidence(ts.addr, writeTemp(t, dir, "evidence.crt", cert), writeTemp(t, dir, "evidence.key", key), ts.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		input := &agentv1.BmpRoutingPeerUp{ObservationId: nonce, ConfiguredRef: originID, OriginSerial: originSerial, ObservedUnixNanos: time.Now().UnixNano(), Message: routingPeerUpWire(t)}
		receipt, err := client.StageRoutingPeer(ctx, input)
		if err != nil || receipt.GetStatus() != "staged" || len(receipt.GetViews()) != 2 {
			t.Fatal("real mTLS routing staging lost complete owned source", receipt, err)
		}
		lanes = append(lanes, lane{tenant.ID, collector, originSerial, client, input, receipt})
	}
	counts := func(lane lane, state string) int {
		var total int
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND state=$3`, lane.tenant, contextID, state).Scan(&total)
		})
		if err != nil {
			t.Fatal(err)
		}
		return total
	}
	for _, lane := range lanes {
		retry, err := lane.client.StageRoutingPeer(ctx, lane.input)
		if err != nil || retry.GetStatus() != "replayed" || len(retry.GetViews()) != 2 || counts(lane, "staging") != 2 || counts(lane, "current") != 0 {
			t.Fatal("real routing retry duplicated or published private metadata", retry, err)
		}
	}
	unbound := proto.Clone(lanes[0].input).(*agentv1.BmpRoutingPeerUp)
	unbound.ObservationId = newUUID(t)
	unbound.ObservedUnixNanos = time.Now().UnixNano()
	unbound.Message[8] = 1
	if _, err := lanes[0].client.StageRoutingPeer(ctx, unbound); err == nil || counts(lanes[0], "staging") != 2 || counts(lanes[1], "staging") != 2 {
		t.Fatal("unbound routing VRF selected or reset a canonical context", err)
	}
	foreign := proto.Clone(lanes[0].input).(*agentv1.BmpRoutingPeerUp)
	foreign.OriginSerial = lanes[1].originSerial
	if _, err := lanes[0].client.StageRoutingPeer(ctx, foreign); err == nil || counts(lanes[0], "staging") != 2 || counts(lanes[1], "staging") != 2 {
		t.Fatal("foreign origin serial admitted or changed tenant routing state", err)
	}
	malformed := proto.Clone(lanes[0].input).(*agentv1.BmpRoutingPeerUp)
	malformed.ObservationId = newUUID(t)
	malformed.ObservedUnixNanos = time.Now().UnixNano()
	malformed.Message = []byte{3, 0, 0}
	refused, err := lanes[0].client.StageRoutingPeer(ctx, malformed)
	if err == nil || refused.GetStatus() != "invalidated" || counts(lanes[0], "staging") != 0 || counts(lanes[1], "staging") != 2 {
		t.Fatal("malformed served routing metadata failed to commit isolated refusal", refused, err)
	}
	if _, err := lanes[0].client.StageRoutingPeer(ctx, lanes[0].input); err == nil || counts(lanes[0], "staging") != 0 {
		t.Fatal("served old routing UUID revived refused source state", err)
	}
}
