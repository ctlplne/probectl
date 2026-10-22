// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// fetchTestBundleCapability is advertised in RegisterResponse.server_capabilities
// only when central test distribution is configured, so an agent knows whether
// pulling is worth a call.
const fetchTestBundleCapability = "agent.fetch_test_bundle.v1"

// TestBundles is the control plane's source of signed central test bundles
// (G9, D-41; internal/testsync.Source). Every method takes the tenant from the
// caller's verified client certificate — the transport never passes a tenant
// read from a request body.
type TestBundles interface {
	// Version returns the tenant's current test-set version (cheap, cached).
	Version(ctx context.Context, tenantID string) (uint64, error)
	// Bundle returns the tenant's signed bundle and the version it carries.
	Bundle(ctx context.Context, tenantID string) (uint64, []byte, error)
}

// WithTestBundles wires central test distribution. nil (the default) keeps it
// off: FetchTestBundle answers FailedPrecondition and agents keep running their
// local tests only.
func (s *Server) WithTestBundles(src TestBundles) *Server {
	s.svc.testBundles = src
	return s
}

// FetchTestBundle serves the calling agent's tenant's signed test set. The
// tenant is the one in the verified client certificate (docs/guardrails.md
// G7-4); nothing in the request can name another tenant. known_version equal
// to the current version short-circuits to not_modified without signing.
func (svc *service) FetchTestBundle(ctx context.Context, req *agentv1.FetchTestBundleRequest) (*agentv1.FetchTestBundleResponse, error) {
	id, err := svc.authenticate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if svc.testBundles == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"central test distribution is not configured (PROBECTL_TESTSYNC_SIGNING_KEY_FILE)")
	}
	current, err := svc.testBundles.Version(ctx, id.TenantID)
	if err != nil {
		svc.log.Error("test bundle version read failed", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
		return nil, status.Error(codes.Unavailable, "test set unavailable")
	}
	if req.GetKnownVersion() != 0 && req.GetKnownVersion() == current {
		return &agentv1.FetchTestBundleResponse{NotModified: true, Version: current}, nil
	}
	version, signed, err := svc.testBundles.Bundle(ctx, id.TenantID)
	if err != nil {
		svc.log.Error("test bundle build failed", "tenant", id.TenantID, "agent", id.AgentID, "error", err.Error())
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, status.FromContextError(err).Err()
		}
		return nil, status.Error(codes.Unavailable, "test set unavailable")
	}
	svc.log.Debug("served test bundle", "tenant", id.TenantID, "agent", id.AgentID,
		"version", version, "known_version", req.GetKnownVersion(), "bytes", len(signed))
	return &agentv1.FetchTestBundleResponse{Version: version, SignedBundle: signed}, nil
}

// testSetStale reports whether the agent's applied version is behind its
// tenant's current one — the heartbeat nudge. Any read failure answers false:
// the agent's own poll interval still converges, and a heartbeat must never
// fail because the test-set store hiccupped.
func (svc *service) testSetStale(ctx context.Context, tenantID string, applied uint64) bool {
	if svc.testBundles == nil {
		return false
	}
	current, err := svc.testBundles.Version(ctx, tenantID)
	if err != nil {
		return false
	}
	return current != applied
}

// currentTestSetVersion is the version advertised in RegisterResponse
// (config_epoch); 0 when distribution is off or the read fails.
func (svc *service) currentTestSetVersion(ctx context.Context, tenantID string) uint64 {
	if svc.testBundles == nil {
		return 0
	}
	v, err := svc.testBundles.Version(ctx, tenantID)
	if err != nil {
		return 0
	}
	return v
}
