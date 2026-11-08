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
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
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

type publicWireLane struct {
	tenant, collector, serial string
	client                    *agent.EvidenceClient
	raw                       agentv1.AgentServiceClient
	source                    *agentv1.PublicRoutingPeerTable
	tail                      uint32
}

type publicWireFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	server    testServer
	gate      *fairness.Gate
	contextID string
	lanes     [2]publicWireLane
}

func newPublicWireFixture(t *testing.T) *publicWireFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	t.Cleanup(cancel)
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	gate := fairness.NewGate(fairness.DefaultPolicy(), nil)
	f := &publicWireFixture{ctx: ctx, pool: pool, gate: gate, contextID: newUUID(t)}
	f.server = startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(gate) })
	site, vrf, nonce := newUUID(t), newUUID(t), newUUID(t)
	for i := range f.lanes {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("public-mrt-wire-%d-%d", i, time.Now().UnixNano()), "public MRT fixture")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		lane := &f.lanes[i]
		lane.tenant, lane.collector, lane.tail = tenant.ID, newUUID(t), uint32(64497+i)
		var cert, key []byte
		for _, uri := range []string{crypto.AgentSPIFFEID(tenant.ID, lane.collector), crypto.EntitySPIFFEID(tenant.ID, lane.collector)} {
			c, k, err := f.server.ca.IssueClientCert(lane.collector, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(c)
			if block == nil {
				t.Fatal("QA public collector certificate missing")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, lane.collector, uri, leaf.SerialNumber.Text(16), leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
			cert, key, lane.serial = c, k, leaf.SerialNumber.Text(16)
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, lane.collector, "public-mrt", "192.0.2.99", "fixture", crypto.AgentSPIFFEID(tenant.ID, lane.collector), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','same-vrf')`, tenant.ID, f.contextID, site, vrf); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'site','site')`, tenant.ID, f.contextID, site); err != nil {
				return err
			}
			return store.NewEntityRegistry(pool).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: lane.collector, Kind: entity.PublicBGP, SourceRef: "ris/mrt_table_dump_v2/rrc00"}, f.contextID, "")
		}); err != nil {
			t.Fatal(err)
		}
		certFile, keyFile := writeTemp(t, t.TempDir(), "evidence.crt", cert), writeTemp(t, t.TempDir(), "evidence.key", key)
		lane.client, err = agent.DialEntityEvidence(f.server.addr, certFile, keyFile, f.server.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = lane.client.Close() })
		lane.raw = f.rawClient(t, lane, certFile, keyFile)
		at := time.Now()
		lane.source = &agentv1.PublicRoutingPeerTable{ConfiguredRef: "ris/mrt_table_dump_v2/rrc00", ObservationId: nonce, ObservedUnixNanos: at.UnixNano(), SourceRecord: publicPeerTableWire(uint32(at.Unix()))}
		f.publish(t, lane)
	}
	return f
}

func (f *publicWireFixture) rawClient(t *testing.T, lane *publicWireLane, certFile, keyFile string) agentv1.AgentServiceClient {
	t.Helper()
	cfg, _, err := crypto.ClientMTLSConfigRotating(certFile, keyFile, f.server.caFile, crypto.EntitySPIFFEID(lane.tenant, lane.collector))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = "localhost"
	conn, err := grpc.NewClient(f.server.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewAgentServiceClient(conn)
}

func (f *publicWireFixture) publish(t *testing.T, lane *publicWireLane) {
	t.Helper()
	if got, err := lane.client.StagePublicRoutingSource(f.ctx, lane.source); err != nil || got.GetStatus() != "staged" {
		t.Fatal("original MRT peer table failed authenticated staging", got, err)
	}
	if got, err := lane.client.StagePublicRoutingSource(f.ctx, lane.source); err != nil || got.GetStatus() != "replayed" {
		t.Fatal("original MRT staging retry changed source identity", got, err)
	}
	for i, afi := range []uint16{1, 2, 0} {
		message := f.message(lane, int64(i+1))
		message.Complete = afi == 0
		if afi != 0 {
			message.Record = publicRIBWire(afi, lane.tail, binary.BigEndian.Uint32(lane.source.SourceRecord[:4]))
		}
		if got, err := lane.client.SubmitPublicRoutingMessage(f.ctx, message); err != nil || got.GetStatus() != "applied" {
			t.Fatal("original MRT record or EOF failed authenticated publication", got, err)
		}
		if got, err := lane.client.SubmitPublicRoutingMessage(f.ctx, message); err != nil || got.GetStatus() != "replayed" {
			t.Fatal("original MRT record retry lost exact identity", got, err)
		}
	}
}

func (f *publicWireFixture) message(lane *publicWireLane, sequence int64) *agentv1.PublicRoutingMessage {
	return &agentv1.PublicRoutingMessage{ConfiguredRef: lane.source.ConfiguredRef, SnapshotId: lane.source.ObservationId, Sequence: sequence, ObservedUnixNanos: time.Now().UnixNano()}
}

func (f *publicWireFixture) read(lane *publicWireLane, address string) (store.BGPPublicRoutingLookup, error) {
	var got store.BGPPublicRoutingLookup
	source := store.BGPPublicRoutingSource{Scope: entity.Scope{TenantID: lane.tenant, ContextID: f.contextID}, CollectorAgentID: lane.collector, SenderSerial: lane.serial, SourceRef: lane.source.ConfiguredRef, ObservedAt: time.Now()}
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(f.ctx, tenancy.ID(lane.tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		got, err = (store.BGPRouting{}).LookupPublicSnapshotInScope(ctx, sc, source, lane.source.ObservationId, netip.MustParseAddr(address), store.BGPRoutingBudget{MemoryBytes: 512 << 20, WorkUnits: 2 << 30, StateBytes: 64 << 30, LeaseDuration: 12 * time.Hour}, 12*time.Hour)
		return err
	})
	return got, err
}

func (f *publicWireFixture) assertCurrent(t *testing.T, lane *publicWireLane) {
	t.Helper()
	for _, address := range []string{"192.0.2.9", "2001:db8::9"} {
		got, err := f.read(lane, address)
		if err != nil || len(got.Paths) != 1 || got.Source.TenantID != lane.tenant || got.Source.ContextID != f.contextID || got.SnapshotID != lane.source.ObservationId {
			t.Fatal("served MRT source lost tenant-owned complete paths", got, err)
		}
		path := got.Paths[0]
		sourceClock := int64(binary.BigEndian.Uint32(lane.source.SourceRecord[:4])) * 1_000_000_000
		if len(path.Path.Segments) != 2 || len(path.Path.Segments[0].Values) != 3 || path.Path.Segments[0].Values[0] != ^uint32(0) || path.Path.Segments[0].Values[1] != lane.tail || path.Path.Segments[0].Values[2] != lane.tail || path.Path.Segments[1].Kind != 1 || path.Peer.Collector != "rrc00" || len(path.Peer.ViewName) != 2 || path.Peer.ViewName[0] != 0 || path.Peer.ViewName[1] != 255 || path.Peer.PeerBGPIdentifier == nil || *path.Peer.PeerBGPIdentifier != 0 || path.Path.Attributes.MRT == nil || path.Path.Attributes.MRT.OriginatedUnixNanos != 0 || path.Path.Attributes.MRT.RecordUnixNanos != sourceClock || path.Path.Attributes.MRT.Sequence != ^uint32(0) || got.SourceObservedUnixNanos != sourceClock || got.ValidUntil.After(time.Unix(0, sourceClock).Add(12*time.Hour)) {
			t.Fatal("served MRT source narrowed original wire facts or borrowed sibling paths", path)
		}
	}
}

// Real issued evidence mTLS, production decoder/writer/current reader and
// application-role TLS Postgres. MRT bytes are synthetic, not a live collector.
func TestPublicRoutingOriginalMRTRealMTLSKeepsTenantCurrentSourceAndWholeRefusal(t *testing.T) {
	f := newPublicWireFixture(t)
	a, b := &f.lanes[0], &f.lanes[1]
	f.assertCurrent(t, a)
	f.assertCurrent(t, b)
	t.Run("mixed-envelope", func(t *testing.T) {
		mixed := proto.Clone(a.source).(*agentv1.PublicRoutingPeerTable)
		mixed.ObservationId, mixed.ObservedUnixNanos = newUUID(t), time.Now().UnixNano()
		_, err := a.raw.SubmitEntityEvidence(f.ctx, &agentv1.SubmitEntityEvidenceRequest{PublicRoutingPeerTable: mixed, FlowRouting: &agentv1.FlowRoutingWitnessBatch{}})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatal("served public MRT accepted a mixed evidence envelope", err)
		}
		f.assertCurrent(t, a)
	})
	t.Run("foreign-snapshot", func(t *testing.T) {
		// First prove matching public UUID/context/ref in both RLS tenants,
		// then replace B so A can attempt a real foreign-only snapshot ID.
		b.source = proto.Clone(b.source).(*agentv1.PublicRoutingPeerTable)
		b.source.ObservationId, b.source.ObservedUnixNanos = newUUID(t), time.Now().UnixNano()
		f.publish(t, b)
		foreign := f.message(a, 4)
		foreign.SnapshotId, foreign.SourceReset = b.source.ObservationId, true
		if _, err := a.client.SubmitPublicRoutingMessage(f.ctx, foreign); err == nil {
			t.Fatal("public MRT sender borrowed an unowned snapshot")
		}
		f.assertCurrent(t, a)
		f.assertCurrent(t, b)
	})
	t.Run("whole-file-producer", func(t *testing.T) {
		original := bytes.Clone(a.source.SourceRecord)
		clock := binary.BigEndian.Uint32(original[:4])
		original = append(original, publicRIBWire(1, a.tail, clock)...)
		original = append(original, publicRIBWire(2, a.tail, clock)...)
		got, err := a.client.ImportPublicMRT(f.ctx, bytes.NewReader(original), agent.DefaultPublicMRTOptions(a.source.ConfiguredRef))
		if err != nil || got.Records != 3 || got.Bytes != int64(len(original)) || got.SnapshotID == a.source.ObservationId {
			t.Fatal("original whole MRT sender failed authenticated complete import", got, err)
		}
		a.source.ObservationId = got.SnapshotID
		f.assertCurrent(t, a)
		f.assertCurrent(t, b)
	})
	t.Run("unissued-serial", func(t *testing.T) {
		cert, key, err := f.server.ca.IssueClientCert(a.collector, crypto.EntitySPIFFEID(a.tenant, a.collector), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		client := f.rawClient(t, a, writeTemp(t, t.TempDir(), "unissued.crt", cert), writeTemp(t, t.TempDir(), "unissued.key", key))
		if _, err := client.SubmitEntityEvidence(f.ctx, &agentv1.SubmitEntityEvidenceRequest{PublicRoutingPeerTable: a.source}); status.Code(err) != codes.Unauthenticated {
			t.Fatal("public MRT accepted a CA-signed but unissued evidence serial", err)
		}
		f.assertCurrent(t, a)
	})
	t.Run("revoked-current-sender", func(t *testing.T) {
		if _, _, err := store.NewAgentIdentities(f.pool).RevokeAgent(f.ctx, a.tenant, a.collector, "fixture"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.client.StagePublicRoutingSource(f.ctx, a.source); err == nil {
			t.Fatal("public MRT accepted a revoked collector on its existing TLS connection")
		}
		if got, err := f.read(a, "192.0.2.9"); !errors.Is(err, store.ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
			t.Fatal("public MRT current reader retained revoked collector authority", got, err)
		}
		f.assertCurrent(t, b)
	})
}

func TestPublicRoutingRealMTLSKnownSourceRefusalCommitsWithoutSiblingDamage(t *testing.T) {
	for _, scenario := range []string{"empty-stage", "malformed-stage", "malformed-frame", "rate-stage", "rate-frame"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPublicWireFixture(t)
			a, b := &f.lanes[0], &f.lanes[1]
			if scenario == "rate-stage" || scenario == "rate-frame" {
				if !f.gate.AdmitN(f.ctx, a.tenant, fairness.MeterEntityEvidenceBytes, 1<<50) {
					t.Fatal("public MRT rate-refusal prerequisite did not consume its own tenant budget")
				}
			}
			var err error
			if scenario == "empty-stage" || scenario == "malformed-stage" || scenario == "rate-stage" {
				replacement := proto.Clone(a.source).(*agentv1.PublicRoutingPeerTable)
				replacement.ObservationId, replacement.ObservedUnixNanos = newUUID(t), time.Now().UnixNano()
				if scenario == "malformed-stage" {
					replacement.SourceRecord = replacement.SourceRecord[:12]
				}
				if scenario == "empty-stage" {
					replacement.SourceRecord = nil
				}
				_, err = a.client.StagePublicRoutingSource(f.ctx, replacement)
			} else {
				message := f.message(a, 4)
				message.Record = publicRIBWire(1, a.tail, uint32(a.source.ObservedUnixNanos/1_000_000_000))[:12]
				_, err = a.client.SubmitPublicRoutingMessage(f.ctx, message)
			}
			if err == nil {
				t.Fatal("served public MRT accepted refused source bytes")
			}
			if got, err := f.read(a, "192.0.2.9"); !errors.Is(err, store.ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
				t.Fatal("served public MRT refusal retained former current paths", got, err)
			}
			f.assertCurrent(t, b)
		})
	}
}

func publicMRTWire(subtype uint16, timestamp uint32, body []byte) []byte {
	raw := binary.BigEndian.AppendUint32(nil, timestamp)
	raw = binary.BigEndian.AppendUint16(raw, 13)
	raw = binary.BigEndian.AppendUint16(raw, subtype)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(body)))
	return append(raw, body...)
}

func publicPeerTableWire(timestamp uint32) []byte {
	body := binary.BigEndian.AppendUint32(nil, 0)
	body = append(body, 0, 2, 0, 255, 0, 1, 2) // binary view, one IPv4/AS4 peer
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, 192, 0, 2, 1)
	body = binary.BigEndian.AppendUint32(body, 64496)
	return publicMRTWire(1, timestamp, body)
}

func publicRIBWire(afi uint16, tail, timestamp uint32) []byte {
	path := []byte{2, 3}
	for _, asn := range []uint32{^uint32(0), tail, tail} {
		path = binary.BigEndian.AppendUint32(path, asn)
	}
	path = append(path, 1, 2)
	path = binary.BigEndian.AppendUint32(path, 64500)
	path = binary.BigEndian.AppendUint32(path, 64501)
	attrs := []byte{0x40, 1, 1, 0, 0x40, 2, byte(len(path))}
	attrs = append(attrs, path...)
	body := binary.BigEndian.AppendUint32(nil, ^uint32(0))
	subtype := uint16(2)
	if afi == 1 {
		body = append(body, 24, 192, 0, 2)
		attrs = append(attrs, 0x40, 3, 4, 192, 0, 2, 1)
	} else {
		subtype = 4
		body = append(body, 32, 0x20, 1, 0x0d, 0xb8)
		attrs = append(attrs, 0x80, 14, 17, 16)
		hop := netip.MustParseAddr("2001:db8::1").As16()
		attrs = append(attrs, hop[:]...)
	}
	body = binary.BigEndian.AppendUint16(body, 1)
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	return publicMRTWire(subtype, timestamp, append(body, attrs...))
}
