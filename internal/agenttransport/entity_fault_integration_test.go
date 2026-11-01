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
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestEntityFaultRealMTLSSenderIsTenantBoundAndRevocationFailsClosed(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ts := startTestServer(ctx, t, pool, func(s *agenttransport.Server) {
		s.WithFaultCorrelator(control.BuildCorrelator(pool, time.Minute, logger))
	})
	a, err := store.NewTenants(pool).Create(ctx,
		fmt.Sprintf("fault-wire-a-%d", time.Now().UnixNano()), "Fault Wire A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.NewTenants(pool).Create(ctx,
		fmt.Sprintf("fault-wire-b-%d", time.Now().UnixNano()), "Fault Wire B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove fault wire tenants: %v", err)
		}
	})
	const target = "10.42.0.1"
	siteByTenant := map[string]string{a.ID: uuid.NewString(), b.ID: uuid.NewString()}
	type wireSender struct {
		tenant, agent, serial, contextID, entityID string
		rpc                                        agentv1.AgentServiceClient
	}
	makeSender := func(tenantID, agentID, sourceKind, vrfLabel string, shared *wireSender) wireSender {
		t.Helper()
		if shared != nil && shared.tenant != tenantID {
			t.Fatal("shared canonical entity belongs to another tenant")
		}
		certPEM, keyPEM, err := ts.ca.IssueClientCert(agentID,
			crypto.EntitySPIFFEID(tenantID, agentID), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("evidence certificate PEM is missing")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		serial := leaf.SerialNumber.Text(16)
		if err := store.NewAgentIdentities(pool).Record(ctx, tenantID, agentID,
			crypto.EntitySPIFFEID(tenantID, agentID), serial, leaf.NotAfter, ""); err != nil {
			t.Fatal(err)
		}
		contextID, entityID := uuid.NewString(), uuid.NewString()
		if shared != nil {
			contextID, entityID = shared.contextID, shared.entityID
		}
		err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				if shared == nil {
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
					(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
					VALUES ($1,$2,$3,$4,'site-a',$5)`,
						tenantID, contextID, siteByTenant[tenantID], uuid.NewString(), vrfLabel); err != nil {
						return err
					}
					if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
					(tenant_id,context_id,id,kind,label)
					VALUES ($1,$2,$3,'device','lab router')`,
						tenantID, contextID, entityID); err != nil {
						return err
					}
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
					(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
					tenantID, agentID, contextID); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
					(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
					VALUES ($1,$2,$3,$4,$5,$6)`,
					tenantID, agentID, sourceKind, target, contextID, entityID); err != nil {
					return err
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		cfg, err := crypto.ClientMTLSConfig(
			writeTemp(t, dir, "evidence.crt", certPEM),
			writeTemp(t, dir, "evidence.key", keyPEM), ts.caFile)
		if err != nil {
			t.Fatal(err)
		}
		cfg.ServerName = "localhost"
		conn, err := grpc.NewClient(ts.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		rpc := agentv1.NewAgentServiceClient(conn)
		if sourceKind == "device_target" || sourceKind == "flow_exporter" {
			// Real sender proof: correlation requires a current address row
			// from each fault's exact evidence SVID, not just the shared anchor.
			ref := "snmp:configured-target"
			if sourceKind == "flow_exporter" {
				ref = "flow:configured-exporter"
			}
			rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			response, err := rpc.SubmitEntityEvidence(rpcCtx,
				&agentv1.SubmitEntityEvidenceRequest{Observations: []*agentv1.EntityEvidenceObservation{{
					ObservationId: uuid.NewString(), SourceKind: sourceKind,
					ConfiguredRef: target, AliasKind: "address", AliasValue: target,
					SourceRef: ref, ObservedUnixNanos: time.Now().UnixNano(),
				}}})
			cancel()
			if err != nil || response.GetAccepted() != 1 || response.GetUnresolved() != 0 {
				t.Fatalf("verified %s address evidence = %+v %v", sourceKind, response, err)
			}
		}
		return wireSender{tenant: tenantID, agent: agentID, serial: serial,
			contextID: contextID, entityID: entityID,
			rpc: rpc}
	}
	red := makeSender(a.ID, "fault-wire-red", "device_target", "vrf-a", nil)
	flow := makeSender(a.ID, "fault-wire-flow", "flow_exporter", "vrf-a", &red)
	blue := makeSender(b.ID, "fault-wire-blue", "device_target", "vrf-a", nil)
	otherVRF := makeSender(a.ID, "fault-wire-other-vrf", "device_target", "vrf-b", nil)
	if otherVRF.contextID == red.contextID || otherVRF.entityID == red.entityID {
		t.Fatal("different VRFs reused the same context or canonical router ID")
	}
	registry := store.NewEntityRegistry(pool)
	for _, sender := range []wireSender{red, otherVRF, blue} {
		got, err := registry.ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(sender.tenant)),
			entity.Scope{TenantID: sender.tenant, ContextID: sender.contextID},
			entity.AliasKey{Kind: entity.AddressAlias, Value: target})
		if err != nil || got.Status != entity.Resolved || got.EntityID != sender.entityID {
			t.Fatalf("same RFC1918 address escaped tenant/VRF scope for %s: %+v %v", sender.agent, got, err)
		}
	}
	// Observe red again after the other VRF exists. An identical address and
	// configured source name in that VRF cannot redirect red's mTLS identity.
	lateRedID := uuid.NewString()
	lateCtx, lateCancel := context.WithTimeout(ctx, 5*time.Second)
	late, err := red.rpc.SubmitEntityEvidence(lateCtx,
		&agentv1.SubmitEntityEvidenceRequest{Observations: []*agentv1.EntityEvidenceObservation{{
			ObservationId: lateRedID, SourceKind: "device_target",
			ConfiguredRef: target, AliasKind: "address", AliasValue: target,
			SourceRef: "snmp:configured-target", ObservedUnixNanos: time.Now().UnixNano(),
		}}})
	lateCancel()
	if err != nil || late.GetAccepted() != 1 {
		t.Fatalf("red evidence after other VRF registration = %+v %v", late, err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.tenant)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var contextID, entityID string
			if err := sc.Q.QueryRow(ctx, `SELECT context_id::text,entity_id::text
				FROM entity_evidence WHERE tenant_id=$1 AND agent_id=$2 AND observation_id=$3`,
				red.tenant, red.agent, lateRedID).Scan(&contextID, &entityID); err != nil {
				return err
			}
			if contextID != red.contextID || entityID != red.entityID {
				t.Errorf("red SVID selected the other VRF's router: %s/%s", contextID, entityID)
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	request := func(id, ref string, at time.Time) *agentv1.SubmitEntityEvidenceRequest {
		return &agentv1.SubmitEntityEvidenceRequest{Faults: []*agentv1.EntityFaultObservation{{
			ObservationId: id, SourceKind: "device_target", ConfiguredRef: ref,
			TargetAddress: target, Kind: "device.poll_failed",
			ObservedUnixNanos: at.UnixNano(),
		}}}
	}
	call := func(sender wireSender, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
		rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return sender.rpc.SubmitEntityEvidence(rpcCtx, req)
	}
	redID, blueID := uuid.NewString(), uuid.NewString()
	redReq := request(redID, target, time.Now())
	if reply, err := call(red, redReq); err != nil || reply.GetFaultsPersisted() != 1 {
		t.Fatalf("verified red fault = %+v %v", reply, err)
	}
	if reply, err := call(red, redReq); err != nil || reply.GetFaultsPersisted() != 1 {
		t.Fatalf("same UUID did not replay its receipt: %+v %v", reply, err)
	}
	if reply, err := call(blue, request(blueID, target, time.Now())); err != nil ||
		reply.GetFaultsPersisted() != 1 {
		t.Fatalf("verified blue fault = %+v %v", reply, err)
	}
	flowReq := &agentv1.SubmitEntityEvidenceRequest{Faults: []*agentv1.EntityFaultObservation{{
		ObservationId: uuid.NewString(), SourceKind: "flow_exporter",
		ConfiguredRef: target, TargetAddress: target,
		Kind: "flow.exporter_silent", ObservedUnixNanos: time.Now().UnixNano(),
	}}}
	if reply, err := call(flow, flowReq); err != nil || reply.GetFaultsPersisted() != 1 {
		t.Fatalf("independent flow SVID fault = %+v %v", reply, err)
	}
	if reply, err := call(flow, flowReq); err != nil || reply.GetFaultsPersisted() != 1 {
		t.Fatalf("flow fault retry did not replay receipt: %+v %v", reply, err)
	}
	// Both SVIDs belong to red's tenant and name the same address, but the
	// device sender cannot borrow the flow sender's active source assignment.
	forgedFlow := &agentv1.SubmitEntityEvidenceRequest{Faults: []*agentv1.EntityFaultObservation{{
		ObservationId: uuid.NewString(), SourceKind: "flow_exporter",
		ConfiguredRef: target, TargetAddress: target,
		Kind: "flow.exporter_silent", ObservedUnixNanos: time.Now().UnixNano(),
	}}}
	if _, err := call(red, forgedFlow); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("same-tenant device SVID borrowed the flow source assignment: %v", err)
	}
	for _, sender := range []wireSender{red, blue} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(sender.tenant)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				var count int
				var signals int
				var contextID, entityID string
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incidents`).Scan(&count); err != nil {
					return err
				}
				if count != 1 {
					t.Errorf("tenant %s saw %d incidents, want one", sender.tenant, count)
					return nil
				}
				if err := sc.Q.QueryRow(ctx, `SELECT entity_context_id::text,entity_id::text,signal_count
					FROM incidents WHERE tenant_id=$1`, sender.tenant).
					Scan(&contextID, &entityID, &signals); err != nil {
					return err
				}
				if contextID != sender.contextID || entityID != sender.entityID {
					t.Errorf("tenant %s resolved foreign or absent entity: %s/%s",
						sender.tenant, contextID, entityID)
				}
				wantSignals := 1
				if sender.tenant == red.tenant {
					wantSignals = 2
				}
				if signals != wantSignals {
					t.Errorf("tenant %s has %d incident signals, want %d",
						sender.tenant, signals, wantSignals)
				}
				if sender.tenant == red.tenant {
					var flowSignals int
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incident_signals
					WHERE tenant_id=$1 AND plane='flow' AND kind='flow.exporter_silent'
					  AND entity_context_id=$2 AND entity_id=$3
					  AND identity_lookup_attempted`,
						sender.tenant, sender.contextID, sender.entityID).Scan(&flowSignals); err != nil {
						return err
					}
					if flowSignals != 1 {
						t.Errorf("independent flow SVID did not resolve the verified red entity: %d signals", flowSignals)
					}
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := call(red, request(uuid.NewString(), "10.42.0.2", time.Now())); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("fault selected another configured device: %v", err)
	}
	setSourceExpiry := func(at *time.Time) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.tenant)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET expires_at=$4
					WHERE tenant_id=$1 AND agent_id=$2 AND source_ref=$3`,
					red.tenant, red.agent, target, at)
				return err
			}); err != nil {
			t.Fatal(err)
		}
	}
	expiredAt := time.Now()
	setSourceExpiry(&expiredAt)
	if _, err := call(red, request(uuid.NewString(), target, time.Now())); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("removed source assignment opened an ungrouped incident: %v", err)
	}
	setSourceExpiry(nil)
	oldFault := request(uuid.NewString(), target, time.Now().Add(-time.Hour))
	if _, err := call(red, oldFault); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("pre-issuance fault entered incident transaction: %v", err)
	}
	setSenderExpiry := func(at time.Time) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.tenant)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET not_after=$4
					WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`,
					red.tenant, red.agent, red.serial, at)
				return err
			}); err != nil {
			t.Fatal(err)
		}
	}
	setSenderExpiry(time.Now().Add(-time.Second))
	if _, err := call(red, request(uuid.NewString(), target, time.Now())); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("database-expired evidence SVID opened a fault: %v", err)
	}
	setSenderExpiry(time.Now().Add(time.Hour))
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.tenant)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities
				SET revoked_at=clock_timestamp(),revoked_by='operator'
				WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3`,
				red.tenant, red.agent, red.serial)
			return err
		}); err != nil {
		t.Fatal(err)
	}
	if _, err := call(red, request(uuid.NewString(), target, time.Now())); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked live mTLS connection opened a fault: %v", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red.tenant)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var incidents, receipts int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM incidents`).Scan(&incidents); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_fault_receipts`).Scan(&receipts); err != nil {
				return err
			}
			if incidents != 1 || receipts != 2 {
				t.Errorf("rejected faults wrote rows: incidents=%d receipts=%d", incidents, receipts)
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
}
