// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type serialEvidenceServer struct {
	agentv1.UnimplementedAgentServiceServer
	serials chan string
}

func (s *serialEvidenceServer) SubmitEntityEvidence(ctx context.Context, request *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("missing verified peer")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) != 1 {
		return nil, errors.New("missing mTLS leaf")
	}
	if _, err := crypto.EntitySPIFFEIDFromCert(info.State.PeerCertificates[0]); err != nil {
		return nil, err
	}
	s.serials <- info.State.PeerCertificates[0].SerialNumber.Text(16)
	return &agentv1.SubmitEntityEvidenceResponse{
		Accepted:        uint32(len(request.GetObservations())),
		FaultsPersisted: uint32(len(request.GetFaults())),
	}, nil
}

func TestEvidenceClientRequiresExactPlaneAndAgent(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const agentID = "22222222-2222-4222-8222-222222222222"
	ca, err := crypto.GenerateCA("entity-client", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	dial := func(uri string) (*EvidenceClient, error) {
		t.Helper()
		cert, key, err := ca.IssueClientCert(agentID, uri, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
		if err := os.WriteFile(certPath, cert, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
		return DialEntityEvidence("127.0.0.1:1", certPath, keyPath, caPath, "")
	}
	if client, err := dial(crypto.AgentSPIFFEID(tenant, agentID)); err == nil {
		_ = client.Close()
		t.Fatal("raw agent SVID opened evidence client")
	}
	client, err := dial(crypto.EntitySPIFFEID(tenant, agentID))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	observationID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	item := entity.Observation{ID: observationID,
		Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget,
			SourceRef: "10.42.0.1"},
		Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"},
		SourceRef: "snmp:router", ObservedAt: time.Now().UTC()}
	request, err := client.encodeEvidence(time.Now(), []entity.Observation{item})
	if err != nil || len(request.GetObservations()) != 1 ||
		request.Observations[0].GetSourceKind() != "device_target" ||
		request.Observations[0].GetAliasValue() != "10.42.0.1" {
		t.Fatalf("encoded evidence = %+v, %v", request, err)
	}
	systemClaim := item
	systemClaim.SourceRef = "snmp:configured-target"
	systemClaim.SystemDescription = "router OS"
	systemName := "  edge-a  "
	systemClaim.SystemName = &systemName
	request, err = client.encodeEvidence(time.Now(), []entity.Observation{systemClaim})
	if err != nil || request.GetObservations()[0].GetSystemDescription() != "router OS" ||
		request.GetObservations()[0].SystemName == nil || request.GetObservations()[0].GetSystemName() != systemName {
		t.Fatalf("system description lost on evidence RPC: %v", err)
	}
	for _, name := range []*string{nil, new(string)} {
		systemClaim.SystemName = name
		request, err = client.encodeEvidence(time.Now(), []entity.Observation{systemClaim})
		if err != nil || (request.GetObservations()[0].SystemName == nil) != (name == nil) {
			t.Fatal("evidence RPC collapsed absent and empty system-name metadata")
		}
	}
	interfaceClaim := item
	interfaceClaim.Alias = entity.AliasKey{Kind: entity.SNMPInterfaceAlias, Value: "4294967295"}
	interfaceClaim.SourceRef = "snmp:ifIndex:4294967295"
	interfaceClaim.InterfaceName = "xe-0/0/7"
	interfaceClaim.InterfaceDescription = "uplink"
	request, err = client.encodeEvidence(time.Now(), []entity.Observation{interfaceClaim})
	if err != nil || request.Observations[0].GetInterfaceName() != "xe-0/0/7" ||
		request.Observations[0].GetInterfaceDescription() != "uplink" {
		t.Fatalf("interface metadata lost on evidence RPC: %+v, %v", request, err)
	}
	neighborClaim := item
	neighborClaim.Alias = entity.AliasKey{Kind: entity.PhysicalNeighborAlias, Value: "neighbor:abc123"}
	neighborClaim.SourceRef = "neighbor:abc123"
	neighborClaim.NeighborProtocol = "lldp"
	neighborClaim.NeighborLocalIfIndex = 4294967295
	neighborClaim.NeighborLocalPortID = "xe-0/0/7"
	neighborClaim.NeighborRemotePortID = "xe-0/0/8"
	neighborClaim.NeighborChassisID = "00:11:22:33:44:55"
	neighborClaim.NeighborDeviceName = "edge-b"
	neighborClaim.NeighborAddress = "10.42.0.2"
	request, err = client.encodeEvidence(time.Now(), []entity.Observation{neighborClaim})
	if err != nil || len(request.GetObservations()) != 1 {
		t.Fatalf("encode neighbor evidence: %+v, %v", request, err)
	}
	encoded := request.GetObservations()[0]
	if encoded.GetNeighborProtocol() != "lldp" ||
		encoded.GetNeighborLocalIfIndex() != 4294967295 ||
		encoded.GetNeighborLocalPortId() != "xe-0/0/7" ||
		encoded.GetNeighborRemotePortId() != "xe-0/0/8" ||
		encoded.GetNeighborChassisId() != "00:11:22:33:44:55" ||
		encoded.GetNeighborDeviceName() != "edge-b" ||
		encoded.GetNeighborManagementAddress() != "10.42.0.2" {
		t.Fatalf("physical neighbor provenance lost on evidence RPC: %+v", encoded)
	}
	item.Source.AgentID = "33333333-3333-4333-8333-333333333333"
	if _, err := client.encodeEvidence(time.Now(), []entity.Observation{item}); err != ErrEvidenceBatchInvalid {
		t.Fatalf("forged agent selected evidence sender: %v", err)
	}
}

func TestEvidenceClientReconnectPinsPlaneAndAgent(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const agentID = "22222222-2222-4222-8222-222222222222"
	ca, err := crypto.GenerateCA("entity-rotation", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "key.pem"), filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	install := func(uri string) {
		t.Helper()
		cert, key, err := ca.IssueClientCert(agentID, uri, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, cert, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	install(crypto.EntitySPIFFEID(tenant, agentID))
	client, err := DialEntityEvidence("127.0.0.1:1", certPath, keyPath, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	initial := client.conn
	install(crypto.EntitySPIFFEID(tenant, agentID))
	if err := client.ReconnectAfterRotation(); err != nil || client.conn == initial || client.needsReconnect {
		t.Fatalf("same-identity renewed SVID did not replace connection: %v", err)
	}
	previous := client.conn
	install(crypto.AgentSPIFFEID(tenant, agentID))
	if err := client.ReconnectAfterRotation(); err != ErrEvidenceBatchInvalid || client.conn != previous || !client.needsReconnect {
		t.Fatalf("wrong-plane rotation was admitted: %v", err)
	}
	observationID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	claim := entity.Observation{ID: observationID,
		Source:    entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"},
		Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"},
		SourceRef: "snmp:router", ObservedAt: time.Now().UTC()}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := client.Submit(ctx, []entity.Observation{claim}); err != ErrEvidenceBatchInvalid {
		t.Fatalf("wrong-plane renewal used old connection: %v", err)
	}
	install(crypto.EntitySPIFFEID(tenant, "33333333-3333-4333-8333-333333333333"))
	if err := client.ReconnectAfterRotation(); err != ErrEvidenceBatchInvalid || client.conn != previous {
		t.Fatalf("wrong-agent rotation was admitted: %v", err)
	}
	install(crypto.EntitySPIFFEID(tenant, agentID))
	if err := client.ReconnectAfterRotation(); err != nil || client.conn == previous || client.needsReconnect {
		t.Fatalf("valid recovery did not replace connection: %v", err)
	}
}

func TestEvidenceClientRotationUsesNewTLSLeaf(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const agentID = "22222222-2222-4222-8222-222222222222"
	ca, err := crypto.GenerateCA("entity-tls-rotation", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCertPath, serverKeyPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
	for path, bytes := range map[string][]byte{serverCertPath: serverCert, serverKeyPath: serverKey} {
		if err := os.WriteFile(path, bytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	serverTLS, err := crypto.ServerMTLSConfig(serverCertPath, serverKeyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	serials := make(chan string, 2)
	agentv1.RegisterAgentServiceServer(server, &serialEvidenceServer{serials: serials})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	certPath, keyPath := filepath.Join(dir, "entity.pem"), filepath.Join(dir, "entity.key")
	install := func() {
		t.Helper()
		cert, key, err := ca.IssueClientCert(agentID, crypto.EntitySPIFFEID(tenant, agentID), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(certPath, cert, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	install()
	client, err := DialEntityEvidence(listener.Addr().String(), certPath, keyPath, caPath, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	observationID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	claim := entity.Observation{ID: observationID,
		Source:    entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "10.42.0.1"},
		Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: "10.42.0.1"},
		SourceRef: "snmp:router", ObservedAt: time.Now().UTC()}
	ctx := context.Background()
	if accepted, _, err := client.Submit(ctx, []entity.Observation{claim}); err != nil || accepted != 1 {
		t.Fatalf("initial mTLS evidence = %d, %v", accepted, err)
	}
	first := <-serials
	faultID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	fault := entity.FaultObservation{ID: faultID,
		Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget,
			SourceRef: "10.42.0.1"},
		Target: "10.42.0.1", Kind: entity.FaultDevicePollFailed,
		ObservedAt: time.Now().UTC()}
	if err := client.SubmitFault(ctx, fault); err != nil {
		t.Fatalf("fault did not use restricted evidence RPC: %v", err)
	}
	if faultSerial := <-serials; faultSerial != first {
		t.Fatal("fault left its evidence-only mTLS connection")
	}
	flowFaultID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	flowFault := entity.FaultObservation{ID: flowFaultID,
		Source: entity.SourceKey{AgentID: agentID, Kind: entity.FlowExporter,
			SourceRef: "10.42.0.2"},
		Target: "10.42.0.2", Kind: entity.FaultFlowExporterSilent,
		ObservedAt: time.Now().UTC()}
	if accepted, err := client.SubmitFaults(ctx,
		[]entity.FaultObservation{fault, flowFault}); err != nil || accepted != 2 {
		t.Fatalf("batched restricted faults = %d, %v", accepted, err)
	}
	if batchSerial := <-serials; batchSerial != first {
		t.Fatal("batched flow fault left the evidence-only mTLS connection")
	}
	wrongAgentFault := fault
	wrongAgentFault.Source.AgentID = "33333333-3333-4333-8333-333333333333"
	if err := client.SubmitFault(ctx, wrongAgentFault); err != ErrEvidenceBatchInvalid {
		t.Fatalf("client accepted a fault claiming another agent: %v", err)
	}
	install()
	if err := client.ReconnectAfterRotation(); err != nil {
		t.Fatal(err)
	}
	if accepted, _, err := client.Submit(ctx, []entity.Observation{claim}); err != nil || accepted != 1 {
		t.Fatalf("renewed mTLS evidence = %d, %v", accepted, err)
	}
	if second := <-serials; second == first {
		t.Fatal("renewal kept the old HTTP/2 TLS certificate")
	}
}
