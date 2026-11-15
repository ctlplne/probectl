// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type recoveryEvidenceServer struct {
	agentv1.UnimplementedAgentServiceServer
	expected map[string]*agentv1.SubmitEntityEvidenceRequest
	received chan string
}

func (s *recoveryEvidenceServer) SubmitEntityEvidence(ctx context.Context, request *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing peer")
	}
	tls, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tls.State.PeerCertificates) != 1 {
		return nil, status.Error(codes.Unauthenticated, "missing verified leaf")
	}
	id, err := crypto.EntitySPIFFEIDFromCert(tls.State.PeerCertificates[0])
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "wrong evidence identity")
	}
	if !proto.Equal(request, s.expected[id.TenantID]) {
		return nil, status.Error(codes.PermissionDenied, "wrong tenant original")
	}
	s.received <- id.TenantID
	return &agentv1.SubmitEntityEvidenceResponse{Accepted: uint32(len(request.GetObservations()))}, nil
}

func TestEvidenceRecoveryKeepsOriginalsAndTwoTenantMTLSIdentity(t *testing.T) {
	const agentID = "22222222-2222-4222-8222-222222222222"
	tenants := []string{"11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333"}
	ca, err := crypto.GenerateCA("evidence-recovery", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caPath := write("ca.pem", ca.CertPEM())
	cert, key, err := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := crypto.ServerMTLSConfig(write("server.pem", cert), write("server.key", key), caPath)
	if err != nil {
		t.Fatal(err)
	}
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := reserve.Addr().String()
	if err := reserve.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	clients := make([]*EvidenceClient, 0, len(tenants))
	claims := make([]entity.Observation, 0, len(tenants))
	server := &recoveryEvidenceServer{expected: make(map[string]*agentv1.SubmitEntityEvidenceRequest), received: make(chan string, len(tenants))}
	for i, tenant := range tenants {
		cert, key, err := ca.IssueClientCert(agentID, crypto.EntitySPIFFEID(tenant, agentID), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		client, err := DialEntityEvidence(addr, write(tenant+".pem", cert), write(tenant+".key", key), caPath, "")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		id, err := crypto.UUIDv4()
		if err != nil {
			t.Fatal(err)
		}
		claim := entity.Observation{ID: id, Source: entity.SourceKey{AgentID: agentID, Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"},
			Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: "192.0.2.1"}, SourceRef: "snmp:configured-target", ObservedAt: time.Now().UTC().Add(-time.Duration(i+1) * time.Second)}
		request, err := client.encodeEvidence(time.Now(), []entity.Observation{claim})
		if err != nil {
			t.Fatal(err)
		}
		server.expected[tenant] = request
		client.conn.Connect()
		for state := client.conn.GetState(); state != connectivity.TransientFailure; state = client.conn.GetState() {
			if !client.conn.WaitForStateChange(ctx, state) {
				t.Fatal("did not establish refused transport", ctx.Err())
			}
		}
		clients, claims = append(clients, client), append(claims, claim)
	}
	results := make(chan error, len(clients))
	for i, client := range clients {
		go func() {
			accepted, unresolved, err := client.Submit(ctx, []entity.Observation{claims[i]})
			if err == nil && (accepted != 1 || unresolved != 0) {
				err = status.Error(codes.Internal, "incomplete original receipt")
			}
			results <- err
		}()
	}
	select {
	case err := <-results:
		t.Fatalf("quiet original discarded before transport recovered: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	// Earlier cancellation wins even while the transport cannot connect.
	short, stop := context.WithTimeout(ctx, 25*time.Millisecond)
	_, _, err = clients[0].Submit(short, []entity.Observation{claims[0]})
	stop()
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatal("unavailable transport ignored caller deadline", err)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	agentv1.RegisterAgentServiceServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)
	for range clients {
		if err := <-results; err != nil {
			t.Fatal("original receipt did not survive transport recovery", err)
		}
	}
	seen := make(map[string]bool)
	for range clients {
		seen[<-server.received] = true
	}
	if len(seen) != len(tenants) {
		t.Fatal("recovery crossed certificate tenant boundaries", seen)
	}
	// The transport may wait for a connection, but must not retry a current
	// source/authorization rejection or substitute the sibling's original.
	if _, _, err := clients[0].Submit(ctx, []entity.Observation{claims[1]}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("recovery bypassed current tenant/original refusal", err)
	}
}
