// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const maxEndpointPackageBytes = wire.EndpointPackageLimit

var errEmptyEndpointPackage = errors.New("approved endpoint package is empty")

func (s *Server) WithEndpointPackageStore(objects objectstore.Store) *Server {
	s.endpointPackageStore = objects
	// A verified package stays in private staging for its entire transfer.
	// Cap aggregate staging on a replica in addition to tenant fairness.
	s.endpointPackageSlots = make(chan struct{}, 4)
	return s
}

// StreamEndpointRolloutPackage adapts the authorized release to the agent
// transport envelope; the certificate supplies the recipient identity.
func (s *Server) StreamEndpointRolloutPackage(ctx context.Context, peer crypto.SPIFFEID, rolloutID, platform string,
	send func(*agentv1.EndpointPackageMetadata, io.Reader) error) error {
	return s.DeliverEndpointRolloutPackage(ctx, peer, rolloutID, platform, func(artifact agent.VerifiedArtifact, size int64, src io.Reader) error {
		return send(&agentv1.EndpointPackageMetadata{
			Version: artifact.Version, Platform: artifact.Endpoint.Platform, PackageDigest: artifact.Digest,
			ExecutableIdentity: artifact.Endpoint.ExecutableIdentity, SizeBytes: size,
		}, src)
	})
}

// DeliverEndpointRolloutPackage stages the exact release bytes from the
// certificate tenant and verifies authorization before sending and before
// completing the transfer. send consumes reader before returning. A caller
// publishes the installer only after successful completion.
func (s *Server) DeliverEndpointRolloutPackage(ctx context.Context, peer crypto.SPIFFEID, rolloutID, platform string,
	send func(agent.VerifiedArtifact, int64, io.Reader) error) error {
	if s.endpointPackageStore == nil || send == nil {
		return apierror.Unavailable("endpoint package storage unavailable")
	}
	artifact, revision, err := s.AuthorizeEndpointRolloutRelease(ctx, peer, rolloutID, platform)
	if err != nil {
		return err
	}
	tenant := peer.TenantID
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	release, err := s.beginEndpointPackage(ctx, tenant)
	if err != nil {
		return err
	}
	defer release()
	tenantObjects, err := s.endpointPackageObjects(ctx, tenant)
	if err != nil {
		return err
	}
	path := endpointPackagePath(artifact)
	stage, size, err := stageEndpointPackage(ctx, tenant, tenantObjects, artifact)
	if err != nil {
		return err
	}
	defer stage.Close()

	if err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := audit.TenantAppend(ctx, sc, "agent:"+peer.AgentID, "rollout.package_read", rolloutID,
			map[string]any{"digest": artifact.Digest, "platform": platform, "revision": revision})
		return err
	}); err != nil {
		return err
	}
	checkRelease := func() error {
		current, currentRevision, err := s.AuthorizeEndpointRolloutRelease(ctx, peer, rolloutID, platform)
		if err != nil {
			return err
		}
		currentObjects, err := s.endpointPackageObjects(ctx, tenant)
		if err != nil {
			return err
		}
		if currentRevision != revision || current.Digest != artifact.Digest || current.Version != artifact.Version ||
			*current.Endpoint != *artifact.Endpoint || currentObjects.Key(path) != tenantObjects.Key(path) {
			return apierror.Conflict("endpoint package release changed during the transfer")
		}
		return nil
	}
	if err := checkRelease(); err != nil {
		return err
	}
	reader, err := stage.Open(ctx)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := send(artifact, size, reader); err != nil {
		return err
	}
	return checkRelease()
}

func endpointPackagePath(artifact agent.VerifiedArtifact) string {
	return "endpoint-packages/" + artifact.Endpoint.Platform + "/" + strings.TrimPrefix(artifact.Digest, "sha256:")
}

func (s *Server) checkStagedEndpointPackage(ctx context.Context, tenant string, artifact agent.VerifiedArtifact) error {
	objects, err := s.endpointPackageObjects(ctx, tenant)
	if err != nil {
		return err
	}
	release, err := s.beginEndpointPackage(ctx, tenant)
	if err != nil {
		return err
	}
	defer release()
	stage, _, err := stageEndpointPackage(ctx, tenant, objects, artifact)
	if err != nil {
		if domain, ok := apierror.As(err); ok && (domain.Kind == apierror.KindNotFound || domain.Kind == apierror.KindTooLarge) {
			return apierror.BadRequest("stage the verified installer in this tenant's package storage before planning the rollout")
		}
		return err
	}
	return stage.Close()
}

func (s *Server) beginEndpointPackage(ctx context.Context, tenant string) (func(), error) {
	releaseQuery := func() {}
	if s.fairnessGate != nil {
		var err error
		releaseQuery, err = s.fairnessGate.BeginQuery(ctx, tenant)
		if err != nil {
			return nil, apierror.RateLimited("tenant endpoint package budget exhausted")
		}
	}
	select {
	case s.endpointPackageSlots <- struct{}{}:
		return func() {
			<-s.endpointPackageSlots
			releaseQuery()
		}, nil
	default:
		releaseQuery()
		return nil, apierror.RateLimited("endpoint package staging is busy")
	}
}

func stageEndpointPackage(ctx context.Context, tenant string, objects objectstore.TenantStore,
	artifact agent.VerifiedArtifact) (*reporting.BodyStage, int64, error) {
	stage, receipt, err := reporting.StageBody(ctx, tenant, reporting.BodyStageLimitsForBytes(maxEndpointPackageBytes),
		func(dst io.Writer) error {
			readCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			n, err := objects.CopyLimited(readCtx, endpointPackagePath(artifact), dst, maxEndpointPackageBytes)
			if err == nil && n == 0 {
				return errEmptyEndpointPackage
			}
			return err
		})
	switch {
	case errors.Is(err, objectstore.ErrNotFound):
		return nil, 0, apierror.NotFound("approved endpoint package is missing")
	case errors.Is(err, objectstore.ErrTooLarge), errors.Is(err, reporting.ErrBodyStageLimit):
		return nil, 0, apierror.TooLarge("approved endpoint package exceeds the transfer budget")
	case errors.Is(err, errEmptyEndpointPackage):
		return nil, 0, apierror.BadRequest(errEmptyEndpointPackage.Error())
	case err != nil:
		return nil, 0, apierror.Unavailable("approved endpoint package could not be read").Wrap(err)
	case "sha256:"+receipt.SHA256 != artifact.Digest:
		_ = stage.Close()
		return nil, 0, apierror.Conflict("stored endpoint package differs from the approved digest")
	default:
		return stage, receipt.Bytes, nil
	}
}

func (s *Server) endpointPackageObjects(ctx context.Context, tenant string) (objectstore.TenantStore, error) {
	if s.endpointPackageStore == nil {
		return nil, apierror.Unavailable("endpoint package storage unavailable")
	}
	target, err := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
	if err != nil {
		return nil, err
	}
	switch target.Model {
	case "", tenancy.IsolationPooled:
		if target.ObjectPrefix == "" || target.ObjectPrefix == objectstore.TenantKey(tenant) {
			return objectstore.ForTenant(s.endpointPackageStore, tenant)
		}
	case tenancy.IsolationSiloed, tenancy.IsolationHybrid:
		if target.ObjectPrefix == tenancy.SiloObjectPrefix(tenant) {
			return objectstore.ForTenantPrefix(s.endpointPackageStore, target.ObjectPrefix, tenant)
		}
	}
	return nil, apierror.Unavailable("endpoint package storage routing is unavailable")
}
