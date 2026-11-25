// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type EndpointPackageSource func(ctx context.Context, peer crypto.SPIFFEID, rolloutID, platform string,
	send func(*agentv1.EndpointPackageMetadata, io.Reader) error) error

// WithEndpointPackages attaches managed installer delivery to the existing
// agent mTLS listener. Call it once before Serve.
func (s *Server) WithEndpointPackages(source EndpointPackageSource) {
	if source != nil {
		agentv1.RegisterEndpointUpdateServiceServer(s.grpc, &endpointUpdateService{agents: s.svc, source: source})
	}
}

type endpointUpdateService struct {
	agentv1.UnimplementedEndpointUpdateServiceServer
	agents *service
	source EndpointPackageSource
}

func (s *endpointUpdateService) DownloadEndpointPackage(req *agentv1.DownloadEndpointPackageRequest,
	stream agentv1.EndpointUpdateService_DownloadEndpointPackageServer) error {
	ctx := stream.Context()
	peer, err := s.agents.authenticate(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, "enrolled device certificate required")
	}
	if req.GetRolloutId() == "" || len(req.GetRolloutId()) > 64 || !wire.IsManagedPlatform(req.GetPlatform()) {
		return status.Error(codes.InvalidArgument, "valid rollout and native platform required")
	}
	// The gRPC stream itself must expire so a client that stops consuming
	// messages cannot hold an installer staging slot indefinitely.
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > wire.EndpointPackageDeadline {
		return status.Error(codes.InvalidArgument, "endpoint package transfer deadline exceeds the budget")
	}
	leaf, err := peerLeafFromContext(ctx)
	if err != nil || leaf.SerialNumber == nil {
		return status.Error(codes.Unauthenticated, "enrolled device certificate required")
	}
	if s.agents.pool == nil {
		return status.Error(codes.Unavailable, "enrolled device registry unavailable")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(peer.TenantID))
	serial := leaf.SerialNumber.Text(16)
	checkRegistration := func() error {
		return tenancy.InTenantReadSnapshot(ctx, s.agents.pool, func(ctx context.Context, sc tenancy.Scope) error {
			registeredAt, err := store.ActiveAgentIdentityRegistration(ctx, sc, peer.AgentID, serial)
			if err != nil {
				return err
			}
			if registeredAt.IsZero() {
				return status.Error(codes.Unauthenticated, "enrolled device certificate is inactive")
			}
			return nil
		})
	}
	if err := checkRegistration(); err != nil {
		return endpointPackageStatus(err)
	}
	err = s.source(ctx, peer, req.GetRolloutId(), req.GetPlatform(), func(metadata *agentv1.EndpointPackageMetadata, src io.Reader) error {
		if err := checkRegistration(); err != nil {
			return err
		}
		return sendEndpointPackage(stream, metadata, src)
	})
	if err != nil {
		return endpointPackageStatus(err)
	}
	// A device may have received all the bytes before the operator revokes its
	// certificate. The endpoint publishes only after this RPC returns success.
	return endpointPackageStatus(checkRegistration())
}

func sendEndpointPackage(stream agentv1.EndpointUpdateService_DownloadEndpointPackageServer,
	metadata *agentv1.EndpointPackageMetadata, src io.Reader) error {
	remaining := metadata.GetSizeBytes()
	if remaining <= 0 || remaining > wire.EndpointPackageLimit {
		return status.Error(codes.DataLoss, "verified endpoint package has an invalid size")
	}
	if err := stream.Send(&agentv1.DownloadEndpointPackageResponse{
		Frame: &agentv1.DownloadEndpointPackageResponse_Metadata{Metadata: metadata},
	}); err != nil {
		return err
	}
	for remaining > 0 {
		// grpc.SendMsg may retain the message for tracing after it returns.
		buf := make([]byte, min(wire.EndpointPackageChunk, remaining))
		n, err := io.ReadFull(src, buf)
		if err != nil {
			return status.Error(codes.DataLoss, "verified endpoint package could not be read in full")
		}
		if err := stream.Send(&agentv1.DownloadEndpointPackageResponse{
			Frame: &agentv1.DownloadEndpointPackageResponse_Chunk{Chunk: buf[:n]},
		}); err != nil {
			return err
		}
		remaining -= int64(n)
	}
	return nil
}

func endpointPackageStatus(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return status.FromContextError(err).Err()
	}
	if domain, ok := apierror.As(err); ok {
		switch domain.Kind {
		case apierror.KindUnauthorized:
			return status.Error(codes.Unauthenticated, "enrolled device certificate required")
		case apierror.KindNotFound, apierror.KindForbidden:
			return status.Error(codes.NotFound, "endpoint package release unavailable")
		case apierror.KindRateLimited, apierror.KindTooLarge:
			return status.Error(codes.ResourceExhausted, "endpoint package transfer budget exhausted")
		case apierror.KindConflict:
			return status.Error(codes.FailedPrecondition, "approved endpoint package release changed")
		}
	}
	return status.Error(codes.Unavailable, "endpoint package could not be delivered")
}
