// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AuthorizeEndpointRolloutRelease resolves a prepared package's authorization
// and revision for a peer already authenticated by the agent mTLS listener.
// The requested plan ID and platform only narrow access. The peer certificate
// supplies the tenant and device IDs. A downloader must use the same tenant
// to open the approved object and recheck the revision before streaming and
// before returning a successful transfer status.
func (s *Server) AuthorizeEndpointRolloutRelease(ctx context.Context, peer crypto.SPIFFEID, rolloutID, platform string) (agent.VerifiedArtifact, int64, error) {
	var artifact agent.VerifiedArtifact
	var revision int64
	if peer.TrustDomain != crypto.TrustDomain || peer.Plane != "agent" || peer.TenantID == "" || peer.AgentID == "" {
		return artifact, 0, apierror.Unauthorized("enrolled device identity required")
	}
	if scoped, ok := tenancy.FromContext(ctx); ok && scoped.String() != peer.TenantID {
		return artifact, 0, apierror.Unauthorized("enrolled device identity required")
	}
	if rolloutID == "" || len(rolloutID) > 64 {
		return artifact, 0, apierror.NotFound("endpoint package release unavailable")
	}
	if s.pool == nil {
		return artifact, 0, apierror.Unavailable("endpoint package release storage unavailable")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(peer.TenantID))
	// Package release is a fresh authorization. An API lifecycle cache may
	// preserve an older status across a read failure, so use the live row.
	status, err := readTenantStatus(ctx, s.pool, peer.TenantID)
	if err != nil {
		return artifact, 0, apierror.Unavailable("tenant lifecycle state is temporarily unavailable").Wrap(err)
	}
	if status != "active" {
		return artifact, 0, apierror.NotFound("endpoint package release unavailable")
	}
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		device, err := (store.Agents{}).Get(ctx, sc, peer.AgentID)
		if err != nil {
			return err
		}
		if device.TenantID != peer.TenantID || device.SPIFFEID != peer.String() || device.Status != "online" ||
			device.EndpointProcess == nil || device.EndpointProcess.Platform != platform {
			return apierror.NotFound("endpoint package release unavailable")
		}
		record, err := (store.Rollouts{}).Get(ctx, sc, rolloutID)
		if err != nil {
			return err
		}
		plan, err := decodeRolloutPlan(record)
		if err != nil {
			return err
		}
		var released bool
		artifact, released = plan.ReleasedEndpointArtifact(peer.AgentID, platform, time.Now())
		if !released {
			return apierror.NotFound("endpoint package release unavailable")
		}
		revision = record.Revision
		return nil
	})
	if err != nil {
		return agent.VerifiedArtifact{}, 0, err
	}
	return artifact, revision, nil
}
