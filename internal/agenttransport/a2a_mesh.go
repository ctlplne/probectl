// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// WithA2AMeshResults attaches the live scheduler and tenant-transaction signal
// writer before the mTLS listener starts.
func (s *Server) WithA2AMeshResults(scheduler *a2a.MeshScheduler, write func(context.Context, tenancy.Scope, incident.Signal) (func(), error)) *Server {
	s.svc.a2aMesh, s.svc.a2aMeshSignal = scheduler, write
	return s
}

func (svc *service) admitA2AMeshCredential(ctx context.Context, id crypto.SPIFFEID) (time.Time, error) {
	if svc.a2aMesh == nil || svc.pool == nil {
		return time.Time{}, status.Error(codes.Unavailable, "A2A mesh result intake unavailable")
	}
	leaf, err := peerLeafFromContext(ctx)
	if err != nil || leaf.SerialNumber == nil {
		return time.Time{}, status.Error(codes.Unauthenticated, "A2A mesh certificate missing")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(id.TenantID))
	var registeredAt time.Time
	err = tenancy.InTenantReadSnapshot(ctx, svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		registeredAt, err = store.ActiveAgentIdentityRegistration(ctx, sc, id.AgentID, leaf.SerialNumber.Text(16))
		return err
	})
	if err != nil {
		return time.Time{}, status.Error(codes.Unavailable, "A2A mesh credential lookup failed")
	}
	if registeredAt.IsZero() {
		return time.Time{}, status.Error(codes.Unauthenticated, "A2A mesh credential is inactive")
	}
	return registeredAt, nil
}

func (svc *service) ingestA2AMeshReport(ctx context.Context, streamID crypto.SPIFFEID, req *agentv1.StreamResultsRequest) error {
	outcome := "rejected"
	defer func() {
		if counter := svc.a2aMeshReports[outcome]; counter != nil {
			counter.Inc()
		}
	}()
	proof := req.GetA2AMeshProof()
	if len(proof.GetMac()) != 32 || len(proof.GetSessionId()) != 32 || len(proof.ProtoReflect().GetUnknown()) != 0 {
		return nil // terminal poison disposition, consistent with malformed results
	}
	if svc.a2aMesh == nil || svc.pool == nil || svc.a2aMeshSignal == nil {
		outcome = "retry"
		return errors.New("A2A mesh report storage unavailable")
	}
	// StreamResults may outlive its certificate or a revocation. Re-check
	// mTLS on each mesh frame and the exact issued serial under the write lock.
	id, err := svc.authenticate(ctx)
	if err != nil || id != streamID {
		return nil
	}
	leaf, err := peerLeafFromContext(ctx)
	if err != nil || leaf.SerialNumber == nil {
		return nil
	}
	report, err := svc.a2aMesh.VerifyReport(id.TenantID, id.AgentID, proof.GetSessionId(), req.GetPayload(), proof.GetMac())
	if err != nil {
		return nil
	}
	if !svc.admitEntityEvidence(ctx, id.TenantID, 1, len(req.GetPayload())) {
		outcome = "retry"
		return errors.New("tenant A2A mesh report budget exceeded")
	}
	ctx = tenancy.WithSiloTableLock(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)))
	signal, degraded := report.DegradedSignal()
	var notify func()
	var inserted bool
	err = tenancy.InTenant(ctx, svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := tenancy.RequireTenantCollection(ctx, sc); err != nil {
			return err
		}
		// Follow the existing incident → audit → registry/credential order.
		if degraded {
			if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('incident:'||$1::text,0))`, sc.Tenant.String()); err != nil {
				return err
			}
			if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
				return err
			}
		}
		var err error
		inserted, err = store.RecordA2AMeshResult(ctx, sc, report, leaf.SerialNumber.Text(16))
		if err != nil || !inserted || !degraded {
			return err
		}
		notify, err = svc.a2aMeshSignal(ctx, sc, signal)
		return err
	})
	if terminalA2AMeshError(err) {
		return nil
	}
	if err != nil {
		outcome = "retry"
		return err
	}
	svc.a2aMesh.RememberReport(report)
	if notify != nil {
		notify()
	}
	// Keep normal A2A metrics and at-least-once result bus delivery. A temporary
	// broker error leaves the agent's bytes in its buffer. On retry the original
	// receipt acknowledges the write without correlating a second incident signal.
	err = tenancy.FencedTenantWrite(ctx, svc.collectionFence, id.TenantID, tenancy.ErrNoTenant, func(ctx context.Context) error {
		return svc.publishResult(ctx, id, report.WireResult)
	})
	if terminalA2AMeshError(err) {
		return nil
	}
	if err != nil {
		outcome = "retry"
		return err
	}
	outcome = "replay"
	if inserted {
		outcome = "accepted"
	}
	return nil
}

func terminalA2AMeshError(err error) bool {
	return errors.Is(err, store.ErrA2AMeshReportRefused) || errors.Is(err, tenancy.ErrTenantWritesFenced) || tenancy.IsProspectCollectionEnded(err)
}
