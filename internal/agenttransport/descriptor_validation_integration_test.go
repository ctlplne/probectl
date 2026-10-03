// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agenttransport"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
)

// GAP-07: hostname, agent_version and capabilities arrive in the RegisterRequest
// payload (untrusted — the tenant comes from the cert, not the body) and fan out
// to the operator CLI, the web console, audit records and the cross-tenant
// provider listing. A crafted value carrying an ANSI/terminal escape or an
// unbounded blob must be rejected at the registration boundary, fail-closed,
// before the agent joins the registry — not merely cleaned at one renderer.
func TestRegisterRejectsMalformedDescriptor(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	ts := startTestServer(ctx, t, pool, func(s *agenttransport.Server) {
		s.WithControlVersion("1.4.0")
	})
	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("gap07-%d", time.Now().UnixNano()), "GAP07 Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	// An ANSI screen-clear + color escape; CR/LF row spoofing; a NUL.
	const escape = "edge\x1b[2J\x1b[1;31mPWNED\r\n\x00"

	cases := []struct {
		name string
		req  *agentv1.RegisterRequest
	}{
		{"hostname_control", &agentv1.RegisterRequest{Hostname: escape, AgentVersion: "1.4.0"}},
		{"hostname_overlong", &agentv1.RegisterRequest{Hostname: strings.Repeat("a", 254), AgentVersion: "1.4.0"}},
		{"version_control", &agentv1.RegisterRequest{Hostname: "ok-host", AgentVersion: "1.4.0\x1b[0m"}},
		{"capability_control", &agentv1.RegisterRequest{Hostname: "ok-host", AgentVersion: "1.4.0", Capabilities: []string{"icmp", escape}}},
		{"capability_overlong", &agentv1.RegisterRequest{Hostname: "ok-host", AgentVersion: "1.4.0", Capabilities: []string{strings.Repeat("c", 65)}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client, _ := agentClient(ctx, t, ts, tn.ID)
			rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			_, err := client.Register(rpcCtx, c.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("malformed descriptor %q must be rejected InvalidArgument, got %v", c.name, status.Code(err))
			}
		})
	}

	// Non-vacuity: a well-formed descriptor is still admitted.
	client, agentID := agentClient(ctx, t, ts, tn.ID)
	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := client.Register(rpcCtx, &agentv1.RegisterRequest{
		Hostname:     agentID,
		AgentVersion: "1.4.0",
		Capabilities: []string{"icmp"},
	}); err != nil {
		t.Fatalf("a clean descriptor must still register, got: %v", err)
	}
}
