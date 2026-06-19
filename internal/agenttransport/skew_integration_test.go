// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package agenttransport_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/imfeelingtheagi/probectl/internal/agenttransport"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
	"github.com/imfeelingtheagi/probectl/internal/store"
)

// agentClient dials the transport with a freshly-issued client cert for a new
// agent identity and returns the gRPC client.
func agentClient(_ context.Context, t *testing.T, ts testServer, tenantID string) (agentv1.AgentServiceClient, string) {
	t.Helper()
	agentID := newUUID(t)
	spiffe := crypto.AgentSPIFFEID(tenantID, agentID)
	dir := t.TempDir()
	cc, ck, err := ts.ca.IssueClientCert(agentID, spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := crypto.ClientMTLSConfig(
		writeTemp(t, dir, "client.crt", cc), writeTemp(t, dir, "client.key", ck), ts.caFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = "localhost"
	conn, err := grpc.NewClient(ts.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agentv1.NewAgentServiceClient(conn), agentID
}

// The control plane enforces the N/N-1 version-skew window at registration: a
// control plane at 1.4.0 admits agents within one minor in BOTH directions, and
// rejects anything wider or across a major boundary — so a rolling upgrade never
// admits an incompatible agent.
func TestRegisterEnforcesVersionSkew(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// Pin the control plane to a real (non-dev) version so the policy is active.
	ts := startTestServer(ctx, t, pool, func(s *agenttransport.Server) {
		s.WithControlVersion("1.4.0")
	})

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("skew-%d", time.Now().UnixNano()), "Skew Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	accepted := []string{"1.4.7", "1.3.0", "1.5.9"} // same, N-1, N+1
	for _, v := range accepted {
		client, agentID := agentClient(ctx, t, ts, tn.ID)
		rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		// Unique hostname per agent (the registry has a UNIQUE (tenant, name)).
		resp, err := client.Register(rpcCtx, &agentv1.RegisterRequest{
			Hostname:     agentID,
			AgentVersion: v,
			Capabilities: []string{"icmp", "future-probe-v2", "icmp"},
		})
		if err != nil {
			t.Fatalf("control 1.4.0 should accept agent %s, got: %v", v, err)
		}
		if resp.GetControlVersion() != "1.4.0" || resp.GetProtocolVersion() != "probectl.agent.v1" {
			t.Fatalf("agent %s negotiation = control %q protocol %q", v, resp.GetControlVersion(), resp.GetProtocolVersion())
		}
		if !slices.Equal(resp.GetAcceptedCapabilities(), []string{"icmp"}) {
			t.Fatalf("agent %s accepted capabilities = %v, want only the known requested capability", v, resp.GetAcceptedCapabilities())
		}
		if !slices.Contains(resp.GetServerCapabilities(), "agent.stream_results") ||
			!slices.Contains(resp.GetServerCapabilities(), "tenant.identity.mtls.v1") {
			t.Fatalf("agent %s server capabilities missing core behavior: %v", v, resp.GetServerCapabilities())
		}
		if slices.Contains(resp.GetServerCapabilities(), "agent.stream_config") {
			t.Fatalf("config push must not be advertised as supported: %v", resp.GetServerCapabilities())
		}
		if v == "1.5.9" {
			stream, err := client.StreamConfig(rpcCtx, &agentv1.StreamConfigRequest{})
			if err == nil {
				_, err = stream.Recv()
			}
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("admitted N+1 agent must still see unsupported behavior as Unimplemented, got %v", status.Code(err))
			}
		}
		cancel()
	}

	rejected := []string{"1.2.0", "1.6.0", "2.0.0"} // skew 2 behind/ahead, major mismatch
	for _, v := range rejected {
		client, agentID := agentClient(ctx, t, ts, tn.ID)
		rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := client.Register(rpcCtx, &agentv1.RegisterRequest{Hostname: agentID, AgentVersion: v})
		cancel()
		if err == nil {
			t.Fatalf("control 1.4.0 should REJECT agent %s", v)
		}
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("agent %s rejection should be FailedPrecondition (upgrade required), got %v", v, status.Code(err))
		}
	}
}

// An explicit minimum-version floor retires older agents even inside the window.
func TestRegisterEnforcesMinVersionFloor(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	ts := startTestServer(ctx, t, pool, func(s *agenttransport.Server) {
		s.WithControlVersion("1.6.0").WithVersionPolicy(lifecycle.Policy{Window: 5, Min: "1.5.0"})
	})
	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("floor-%d", time.Now().UnixNano()), "Floor Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// 1.5.0 is at the floor → accepted; 1.4.0 is below it → rejected even within ±2.
	client, agentID := agentClient(ctx, t, ts, tn.ID)
	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if _, err := client.Register(rpcCtx, &agentv1.RegisterRequest{Hostname: agentID, AgentVersion: "1.5.0"}); err != nil {
		t.Fatalf("agent at the floor should be accepted: %v", err)
	}
	cancel()

	client2, agentID2 := agentClient(ctx, t, ts, tn.ID)
	rpcCtx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	_, err = client2.Register(rpcCtx2, &agentv1.RegisterRequest{Hostname: agentID2, AgentVersion: "1.4.0"})
	cancel2()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("agent below the floor should be rejected, got %v", status.Code(err))
	}
}
