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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func routingPeerUpWire(t *testing.T) []byte {
	return routingPeerUpWireForFormat(t, false)
}

func routingPeerUpWireForFormat(t *testing.T, frr bool) []byte {
	t.Helper()
	open := make([]byte, 29)
	for i := range 16 {
		open[i] = 255
	}
	open[18], open[19] = 1, 4
	binary.BigEndian.PutUint16(open[20:22], 64512)
	binary.BigEndian.PutUint16(open[22:24], 180)
	copy(open[24:28], []byte{192, 0, 2, 1})
	options := []byte{2, 18, 65, 4, 0, 0, 252, 0, 1, 4, 0, 1, 0, 1, 1, 4, 0, 2, 0, 1}
	if frr {
		// Synthetic known serializer shape: empty ADD-PATH and no IPv6 MP
		// declaration. Both original OPENs must survive without byte repair.
		options = []byte{2, 8, 65, 4, 0, 0, 252, 0, 69, 0}
	}
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
	proveRoutingStagingMTLS(t, "")
}

func TestRoutingPeerUpRateRefusalInvalidatesOnlyItsCurrentOwnedSource(t *testing.T) {
	proveRoutingStagingMTLS(t, "peer-up-rate")
}

func TestRoutingMalformedUnboundPeerUpPreservesKnownContexts(t *testing.T) {
	proveRoutingStagingMTLS(t, "malformed-unbound")
}

func TestRoutingFRRProfileRequiresCurrentOperatorBindingThroughRealMTLS(t *testing.T) {
	proveRoutingStagingMTLS(t, "frr-profile")
}

func TestRoutingMappedVRFRequiresCurrentBindingThroughRealMTLS(t *testing.T) {
	proveRoutingStagingMTLS(t, "mapped-vrf")
}

func proveRoutingStagingMTLS(t *testing.T, scenario string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	ts := startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(gate) })
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
		if scenario == "frr-profile" || scenario == "mapped-vrf" {
			input.Message = routingPeerUpWireForFormat(t, true)
			if scenario == "mapped-vrf" {
				for j := 8; j < 16; j++ {
					input.Message[j] = 255
				}
			}
			if _, err := client.StageRoutingPeer(ctx, input); err == nil {
				t.Fatal("routing sender enabled a serializer without current operator configuration")
			}
			// Storage fixture only: the public operator writer is proved
			// separately. Identical canonical IDs in each RLS tenant are deliberate.
			bindings, err := json.Marshal([]map[string]any{{"id": newUUID(t), "context_id": contextID, "router_id": routerID,
				"distinguisher": fmt.Sprintf("%x", input.Message[8:16]), "bgp_identifier": "192.0.2.1", "families": []uint16{1, 2}, "source_format": store.BGPRoutingSourceFRRLocRIBV1}})
			if err != nil {
				t.Fatal(err)
			}
			if err := tenancy.InTenant(tenantCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET routing_epoch=$4,routing_bindings=$5::jsonb,routing_assigned_at=clock_timestamp()
 WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='bmp_peer' AND source_ref=$3`, tenant.ID, collector, originID, newUUID(t), string(bindings))
				return err
			}); err != nil {
				t.Fatal(err)
			}
			input.ObservedUnixNanos = time.Now().UnixNano()
		}
		receipt, err := client.StageRoutingPeer(ctx, input)
		if err != nil || receipt.GetStatus() != "staged" || len(receipt.GetViews()) != 2 {
			t.Fatal("real mTLS routing staging lost complete owned source", receipt, err)
		}
		if scenario == "frr-profile" || scenario == "mapped-vrf" {
			if err := tenancy.InTenant(tenantCtx, pool, func(ctx context.Context, sc tenancy.Scope) error {
				var total int
				err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1 AND peer_identity->>'SourceFormat'=$2
 AND decode(peer_identity->>'SentOpen','base64')=$3 AND decode(peer_identity->>'ReceivedOpen','base64')=$3`, tenant.ID, store.BGPRoutingSourceFRRLocRIBV1, input.Message[68:107]).Scan(&total)
				if err == nil && total != 2 {
					t.Fatal("stored serializer lost original OPEN bytes or complete family metadata", total)
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
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
	if scenario == "malformed-unbound" {
		malformedUnbound := proto.Clone(unbound).(*agentv1.BmpRoutingPeerUp)
		malformedUnbound.ObservationId = newUUID(t)
		malformedUnbound.Message = malformedUnbound.Message[:70]
		binary.BigEndian.PutUint32(malformedUnbound.Message[1:5], uint32(len(malformedUnbound.Message)))
		if _, err := lanes[0].client.StageRoutingPeer(ctx, malformedUnbound); err == nil || counts(lanes[0], "staging") != 2 || counts(lanes[1], "staging") != 2 {
			t.Fatal("malformed unbound routing view retired a known canonical context", err)
		}
		// A complete nonzero selector is checked against current storage bindings.
		// A truncated selector has no safe target; it must be refused before the
		// source-wide invalidation path can retire any known canonical context.
		truncatedSelector := proto.Clone(unbound).(*agentv1.BmpRoutingPeerUp)
		truncatedSelector.ObservationId = newUUID(t)
		truncatedSelector.Message = truncatedSelector.Message[:40]
		binary.BigEndian.PutUint32(truncatedSelector.Message[1:5], uint32(len(truncatedSelector.Message)))
		if _, err := lanes[0].client.StageRoutingPeer(ctx, truncatedSelector); err == nil || counts(lanes[0], "staging") != 2 || counts(lanes[1], "staging") != 2 {
			t.Fatal("truncated unbound routing selector retired a known canonical context", err)
		}
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
	// Continue through the same actual restricted mTLS connection: both families
	// retain known paths privately until their own exclusive completion markers.
	streamNonce := newUUID(t)
	for i := range lanes {
		input := proto.Clone(lanes[i].input).(*agentv1.BmpRoutingPeerUp)
		input.ObservationId, input.ObservedUnixNanos = streamNonce, time.Now().UnixNano()
		if _, err := lanes[i].client.StageRoutingPeer(ctx, input); err != nil {
			t.Fatal(err)
		}
		lanes[i].input = input
		for n, mode := range []string{"routes", "v4-eor", "v6-eor"} {
			raw := &agentv1.BmpRoutingMessage{ConfiguredRef: input.ConfiguredRef, OriginSerial: input.OriginSerial, Generation: streamNonce, Sequence: int64(n + 1), ObservedUnixNanos: time.Now().UnixNano(), Message: routingUpdateWire(input.Message, mode, uint32(64496+i))}
			got, err := lanes[i].client.SubmitRoutingMessage(ctx, raw)
			if err != nil || got.GetStatus() != "applied" {
				t.Fatal("served whole routing message failed", mode, got, err)
			}
			if n == 0 && counts(lanes[i], "current") != 0 || n == 1 && counts(lanes[i], "current") != 1 || n == 2 && counts(lanes[i], "current") != 2 {
				t.Fatal("served routing message invented family completeness")
			}
			if n == 2 {
				retry, err := lanes[i].client.SubmitRoutingMessage(ctx, raw)
				if err != nil || retry.GetStatus() != "replayed" {
					t.Fatal("served routing retry changed current source", retry, err)
				}
			}
		}
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lanes[i].tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var total int
			err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries WHERE tenant_id=$1 AND generation=$2 AND segments::text LIKE $3`, lanes[i].tenant, streamNonce, fmt.Sprintf("%%%d%%", 64496+i)).Scan(&total)
			if err == nil && total != 2 {
				t.Fatal("served routing fields lost complete tenant-owned paths", total)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	raw := &agentv1.BmpRoutingMessage{ConfiguredRef: lanes[0].input.ConfiguredRef, OriginSerial: lanes[0].input.OriginSerial, Generation: streamNonce, Sequence: 4, ObservedUnixNanos: time.Now().UnixNano(), Message: routingUpdateWire(lanes[0].input.Message, "routes", 64496)}
	unboundFrame := proto.Clone(raw).(*agentv1.BmpRoutingMessage)
	unboundFrame.Message[8] = 1
	if _, err := lanes[0].client.SubmitRoutingMessage(ctx, unboundFrame); err == nil || counts(lanes[0], "current") != 2 || counts(lanes[1], "current") != 2 {
		t.Fatal("unbound routing UPDATE changed canonical global state")
	}
	raw.Message = append(raw.Message, 0)
	binary.BigEndian.PutUint32(raw.Message[1:5], uint32(len(raw.Message)))
	got, err := lanes[0].client.SubmitRoutingMessage(ctx, raw)
	if err == nil || got.GetStatus() != "invalidated" || counts(lanes[0], "current") != 0 || counts(lanes[1], "current") != 2 {
		t.Fatal("malformed served routing frame retained partial or foreign state", got, err)
	}
	// Restore the paired source so rate refusal must preserve another current
	// tenant, rather than merely leaving an already invalid sibling unchanged.
	restored := proto.Clone(lanes[0].input).(*agentv1.BmpRoutingPeerUp)
	restored.ObservationId, restored.ObservedUnixNanos = newUUID(t), time.Now().UnixNano()
	if _, err := lanes[0].client.StageRoutingPeer(ctx, restored); err != nil {
		t.Fatal(err)
	}
	for n, mode := range []string{"routes", "v4-eor", "v6-eor"} {
		req := &agentv1.BmpRoutingMessage{ConfiguredRef: restored.ConfiguredRef, OriginSerial: restored.OriginSerial, Generation: restored.ObservationId, Sequence: int64(n + 1), ObservedUnixNanos: time.Now().UnixNano(), Message: routingUpdateWire(restored.Message, mode, 64496)}
		if _, err := lanes[0].client.SubmitRoutingMessage(ctx, req); err != nil {
			t.Fatal(err)
		}
	}
	if !gate.AdmitN(ctx, lanes[1].tenant, fairness.MeterEntityEvidenceBytes, 1<<50) {
		t.Fatal("rate refusal prerequisite could not consume tenant byte allowance")
	}
	rejected := &agentv1.BmpRoutingMessage{ConfiguredRef: lanes[1].input.ConfiguredRef, OriginSerial: lanes[1].input.OriginSerial, Generation: streamNonce, Sequence: 4, ObservedUnixNanos: time.Now().UnixNano(), Message: routingUpdateWire(lanes[1].input.Message, "v4-eor", 64497)}
	if scenario == "peer-up-rate" {
		replacement := proto.Clone(lanes[1].input).(*agentv1.BmpRoutingPeerUp)
		replacement.ObservationId, replacement.ObservedUnixNanos = newUUID(t), time.Now().UnixNano()
		if _, err := lanes[1].client.StageRoutingPeer(ctx, replacement); err == nil || counts(lanes[1], "current") != 0 || counts(lanes[0], "current") != 2 {
			t.Fatal("rate-refused routing Peer Up retained stale or foreign current state", err)
		}
	} else {
		if _, err := lanes[1].client.SubmitRoutingMessage(ctx, rejected); err == nil || counts(lanes[1], "current") != 0 || counts(lanes[0], "current") != 2 {
			t.Fatal("rate-refused routing frame retained stale or foreign current state", err)
		}
	}
	reset := &agentv1.BmpRoutingMessage{ConfiguredRef: restored.ConfiguredRef, OriginSerial: restored.OriginSerial, Generation: restored.ObservationId, Sequence: 4, ObservedUnixNanos: time.Now().UnixNano(), SourceReset: true}
	if got, err := lanes[0].client.SubmitRoutingMessage(ctx, reset); err != nil || got.GetStatus() != "invalidated" || got.GetGeneration() != reset.Generation || got.GetSequence() != reset.Sequence || counts(lanes[0], "current") != 0 {
		t.Fatal("served source closure retained current routing state", got, err)
	}
}

func routingUpdateWire(up []byte, mode string, asn uint32) []byte {
	raw := append([]byte(nil), up[:48]...)
	raw[5] = 0
	attrs := []byte{}
	nlri := []byte{}
	switch mode {
	case "routes":
		attrs = []byte{64, 1, 1, 0, 64, 2, 6, 2, 1}
		attrs = binary.BigEndian.AppendUint32(attrs, asn)
		attrs = append(attrs, 64, 3, 4, 192, 0, 2, 99)
		mp := []byte{0, 2, 1, 16, 32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 48, 32, 1, 13, 184, 0, 1}
		attrs = append(attrs, 128, 14, byte(len(mp)))
		attrs = append(attrs, mp...)
		nlri = []byte{24, 192, 0, 2}
	case "v6-eor":
		attrs = []byte{128, 15, 3, 0, 2, 1}
	}
	update := make([]byte, 19)
	for i := range 16 {
		update[i] = 255
	}
	update[18] = 2
	update = append(update, 0, 0)
	update = binary.BigEndian.AppendUint16(update, uint16(len(attrs)))
	update = append(update, attrs...)
	update = append(update, nlri...)
	binary.BigEndian.PutUint16(update[16:18], uint16(len(update)))
	raw = append(raw, update...)
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	return raw
}
