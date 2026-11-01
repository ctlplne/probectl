// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A new correlator instance must read the original verified tuple from
// Postgres. Overlapping private addresses in two VRFs and two tenants cannot
// join, even though the legacy target/prefix rule would join them.
func TestIncidentVerifiedIdentitySurvivesRestartAndSeparatesContexts(t *testing.T) {
	_, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "incident-identity-a"), freshTenant(t, db, "incident-identity-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove incident identity tenants: %v", err)
		}
	})
	contextA, contextOther := gouuid.NewString(), gouuid.NewString()
	entityA, entityOther, entityB := gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
	type sender struct {
		tenant, contextID, entityID, agent, serial, target string
	}
	seed := func(tenant, routingContext, entityID, agent, target string) sender {
		t.Helper()
		serialNumber, ok := new(big.Int).SetString(strings.ReplaceAll(gouuid.NewString(), "-", ""), 16)
		if !ok || serialNumber.Sign() <= 0 {
			t.Fatal("invalid fixture serial")
		}
		serial := serialNumber.Text(16)
		if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(), tenant,
			agent, crypto.EntitySPIFFEID(tenant, agent), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatalf("record evidence sender %s: %v", agent, err)
		}
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,$5,$6)
				ON CONFLICT (tenant_id,id) DO NOTHING`, tenant, routingContext,
				gouuid.NewString(), gouuid.NewString(), "site-"+routingContext, "vrf-"+routingContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device',$4)`,
				tenant, routingContext, entityID, agent); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenant, agent, routingContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'device_target',$3,$4,$5)`,
				tenant, agent, target, routingContext, entityID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
				 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address',$5,
				        'snmp','router',$6,'device_target',$5,clock_timestamp(),$7)`,
				tenant, routingContext, gouuid.NewString(), entityID, target, agent, serial)
			return err
		}); err != nil {
			t.Fatalf("seed verified incident source %s: %v", agent, err)
		}
		return sender{tenant, routingContext, entityID, agent, serial, target}
	}
	red := seed(a, contextA, entityA, "snmp-red", "10.42.0.1")
	otherVRF := seed(a, contextOther, entityOther, "snmp-red-other-vrf", "10.42.0.1")
	blue := seed(b, contextA, entityB, "snmp-blue", "10.42.0.1")
	neighborID := gouuid.NewString()
	_ = seed(a, contextA, neighborID, "snmp-red-neighbor", "10.42.0.9")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	firstCorrelator := BuildCorrelator(db.Pool(), 5*time.Minute, logger)
	signal := func(tenant, plane, target string) incident.Signal {
		return incident.Signal{TenantID: tenant, Plane: plane, Kind: "fault",
			Target: target, OccurredAt: time.Now()}
	}
	source := func(s sender) incident.AuthenticatedIdentitySource {
		uri, err := url.Parse(crypto.EntitySPIFFEID(s.tenant, s.agent))
		if err != nil {
			t.Fatal(err)
		}
		serial, ok := new(big.Int).SetString(s.serial, 16)
		if !ok {
			t.Fatal("invalid fixture serial")
		}
		leaf := &x509.Certificate{Raw: []byte(s.serial), URIs: []*url.URL{uri},
			SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(time.Hour)}
		out, err := incident.AuthenticatedSourceFromTLS(tls.ConnectionState{
			HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains: [][]*x509.Certificate{{leaf}},
		}, "device_target", s.target)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	first, err := firstCorrelator.IngestAuthenticated(context.Background(),
		signal(a, "device", "10.42.0.1"), source(red))
	if err != nil || first.IdentityContextID != contextA || first.IdentityEntityID != entityA {
		t.Fatalf("seed verified incident: %+v %v", first, err)
	}
	// An interface IP is retained on its ifIndex entity, but the current
	// address and sender proof must project it to the parent device. The
	// second tenant owns the same context UUID and private interface IP.
	addInterfaceAddress := func(s sender) {
		t.Helper()
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(s.tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			interfaceID := gouuid.NewString()
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label,parent_entity_id,
				 source_agent_id,configured_ref,interface_index)
				VALUES ($1,$2,$3,'interface','ifIndex 7',$4,$5,$6,7)`,
				s.tenant, s.contextID, interfaceID, s.entityID, s.agent, s.target); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
				 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address','10.42.0.254',
				        'snmp','snmp:ifIndex:7',$5,'device_target',$6,clock_timestamp(),$7)`,
				s.tenant, s.contextID, gouuid.NewString(), interfaceID, s.agent, s.target, s.serial)
			return err
		}); err != nil {
			t.Fatalf("seed interface address for %s: %v", s.tenant, err)
		}
	}
	addInterfaceAddress(red)
	addInterfaceAddress(blue)
	ctxA := tenancy.WithTenant(context.Background(), tenancy.ID(a))
	// A fresh control-plane replica reads the persisted root identity before
	// deciding whether a different raw target belongs to it.
	restarted := BuildCorrelator(db.Pool(), 5*time.Minute, logger)
	joined, err := restarted.IngestAuthenticated(context.Background(),
		signal(a, "flow", "10.42.0.254"), source(red))
	if err != nil || joined.ID != first.ID || joined.SignalCount != 2 ||
		joined.IdentityEntityID != entityA {
		t.Fatalf("restart lost verified identity join: %+v %v", joined, err)
	}
	foreignInterface, err := restarted.IngestAuthenticated(context.Background(),
		signal(b, "device", "10.42.0.254"), source(blue))
	if err != nil || foreignInterface.ID == first.ID ||
		foreignInterface.IdentityContextID != contextA || foreignInterface.IdentityEntityID != entityB {
		t.Fatalf("paired tenant interface IP crossed identity boundary: %+v %v", foreignInterface, err)
	}
	var joinedTimeline *incident.Incident
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var loadErr error
			joinedTimeline, loadErr = (store.Incidents{}).Get(ctx, sc, joined.ID)
			return loadErr
		}); err != nil || joinedTimeline == nil || len(joinedTimeline.Signals) != 2 ||
		joinedTimeline.Signals[1].IdentityEntityID != entityA {
		t.Fatalf("restart lost verified signal evidence: %+v %v", joinedTimeline, err)
	}
	// A second, independently issued flow sender observes another address of
	// the same router. Its fault must join the SNMP-rooted incident through the
	// verified tenant/context/entity tuple, not by a coincidental raw address.
	flowAgent, flowTarget := "flow-red", "10.42.0.254"
	flowSerialNumber, ok := new(big.Int).SetString(strings.ReplaceAll(gouuid.NewString(), "-", ""), 16)
	if !ok || flowSerialNumber.Sign() <= 0 {
		t.Fatal("invalid flow sender fixture serial")
	}
	flowSerial := flowSerialNumber.Text(16)
	if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(), a,
		flowAgent, crypto.EntitySPIFFEID(a, flowAgent), flowSerial,
		time.Now().Add(time.Hour), ""); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(ctxA, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, a, flowAgent, contextA); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,$2,'flow_exporter',$3,$4,$5)`,
			a, flowAgent, flowTarget, contextA, entityA); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
			 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
			VALUES ($1,$2,$3,$3,$4,'address',$5,
			        'flow','flow:ipfix:domain:7',$6,'flow_exporter',$5,clock_timestamp(),$7)`,
			a, contextA, gouuid.NewString(), entityA, flowTarget, flowAgent, flowSerial)
		return err
	}); err != nil {
		t.Fatalf("seed independent flow sender: %v", err)
	}
	uri, err := url.Parse(crypto.EntitySPIFFEID(a, flowAgent))
	if err != nil {
		t.Fatal(err)
	}
	flowLeaf := &x509.Certificate{Raw: []byte(flowSerial), URIs: []*url.URL{uri},
		SerialNumber: flowSerialNumber, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour)}
	flowSource, err := incident.AuthenticatedSourceFromTLS(tls.ConnectionState{
		HandshakeComplete: true, PeerCertificates: []*x509.Certificate{flowLeaf},
		VerifiedChains: [][]*x509.Certificate{{flowLeaf}},
	}, "flow_exporter", flowTarget)
	if err != nil {
		t.Fatal(err)
	}
	faultID := gouuid.NewString()
	flowFault := incident.Signal{TenantID: a, Plane: "flow",
		Kind: "flow.exporter_silent", Target: flowTarget, OccurredAt: time.Now(),
		Attributes: map[string]string{entity.AttrFaultObservationID: faultID}}
	flowJoined, err := restarted.IngestAuthenticatedFault(context.Background(),
		flowFault, flowSource, faultID)
	if err != nil || flowJoined == nil || flowJoined.ID != first.ID ||
		flowJoined.IdentityContextID != contextA || flowJoined.IdentityEntityID != entityA {
		t.Fatalf("real flow sender failed verified cross-plane join: %+v %v", flowJoined, err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			repo := store.Incidents{}
			if _, _, err := repo.CreateUngroupOverride(ctx, sc, joined.ID,
				joinedTimeline.Signals[1].ID, "separate flow fault", "operator-a"); err != nil {
				return err
			}
			probe := signal(a, "flow", "10.42.0.254")
			probe.IdentityLookupAttempted = true
			probe.IdentityContextID, probe.IdentityEntityID = contextA, entityA
			own, err := repo.ActiveCorrelationOverrides(ctx, sc, probe)
			if err != nil {
				return err
			}
			probe.IdentityContextID, probe.IdentityEntityID = contextOther, entityOther
			other, err := repo.ActiveCorrelationOverrides(ctx, sc, probe)
			if err != nil {
				return err
			}
			if len(own) != 1 || len(other) != 0 {
				t.Fatalf("override leaked across reused VRF address: own=%+v other=%+v", own, other)
			}
			return nil
		}); err != nil {
		t.Fatalf("verify scoped override after restart: %v", err)
	}
	other, err := restarted.IngestAuthenticated(context.Background(),
		signal(a, "device", "10.42.0.1"), source(otherVRF))
	if err != nil || other.ID == first.ID || other.IdentityContextID != contextOther {
		t.Fatalf("same private IP joined another VRF: %+v %v", other, err)
	}
	foreign, err := restarted.IngestAuthenticated(context.Background(),
		signal(b, "device", "10.42.0.1"), source(blue))
	if err != nil || foreign.ID == first.ID || foreign.IdentityEntityID != entityB {
		t.Fatalf("same private IP joined another tenant: %+v %v", foreign, err)
	}
	spoofed, err := restarted.IngestAuthenticated(context.Background(),
		signal(a, "device", "10.42.0.9"), source(red))
	if err != nil || spoofed.IdentityEntityID != "" ||
		spoofed.IdentityContextID != contextA || !spoofed.IdentityLookupAttempted {
		t.Fatalf("sender claimed a neighbor's unique address: %+v %v", spoofed, err)
	}
	// A new replica must read the unresolved marker from Postgres and refuse
	// to join a later contextless signal merely because the private IP matches.
	legacy, err := BuildCorrelator(db.Pool(), 5*time.Minute, logger).
		Ingest(context.Background(), signal(a, "bgp", "10.42.0.9"))
	if err != nil || legacy.ID == spoofed.ID {
		t.Fatalf("unresolved source fell back to raw address after restart: %+v %v", legacy, err)
	}
	forgedSender := red
	forgedSender.serial = blue.serial
	forged := source(forgedSender)
	refused, err := restarted.IngestAuthenticated(context.Background(),
		signal(a, "device", "10.42.0.1"), forged)
	if err != nil || refused.ID == first.ID || !refused.IdentityLookupAttempted ||
		refused.IdentityEntityID != "" {
		t.Fatalf("foreign sender serial created a canonical join: %+v %v", refused, err)
	}
	// An address first observed after a fault cannot attach that older fault
	// to the now-current entity. Keep its verified context as a tombstone.
	faultAt := time.Now().UTC().Truncate(time.Microsecond)
	time.Sleep(time.Millisecond)
	if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(a)),
		db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
			(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
			 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
			VALUES ($1,$2,$3,$3,$4,'address','10.42.0.77',
			        'snmp','router',$5,'device_target','10.42.0.1',clock_timestamp(),$6)`,
				a, contextA, gouuid.NewString(), entityA, red.agent, red.serial)
			return err
		}); err != nil {
		t.Fatalf("seed later address evidence: %v", err)
	}
	olderFault := signal(a, "device", "10.42.0.77")
	olderFault.OccurredAt = faultAt
	preEvidence, err := restarted.IngestAuthenticated(context.Background(), olderFault, source(red))
	if err != nil || preEvidence.IdentityContextID != contextA ||
		preEvidence.IdentityEntityID != "" || !preEvidence.IdentityLookupAttempted {
		t.Fatalf("later evidence retroactively resolved earlier fault: %+v %v", preEvidence, err)
	}
	// The flow sender still has a current claim on 10.42.0.254. Moving only
	// the SNMP source to a different device must retire its old interface
	// address, rather than borrowing the flow row's still-resolved device.
	if err := tenancy.InTenant(ctxA, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
			SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id=$3
			  AND source_kind='device_target' AND source_ref=$4`,
			neighborID, a, red.agent, red.target)
		return err
	}); err != nil {
		t.Fatalf("reanchor old interface sender: %v", err)
	}
	staleInterfaceFault, err := restarted.IngestAuthenticated(context.Background(),
		signal(a, "device", "10.42.0.254"), source(red))
	if err != nil || staleInterfaceFault.IdentityContextID != contextA ||
		staleInterfaceFault.IdentityEntityID != "" || staleInterfaceFault.ID == first.ID {
		t.Fatalf("reanchored interface borrowed another sender's current support: %+v %v",
			staleInterfaceFault, err)
	}
}
