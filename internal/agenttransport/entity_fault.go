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

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errEntityFaultPeer = errors.New("entity fault: verified evidence peer is required")

type entityFaultSubmission struct {
	source incident.AuthenticatedIdentitySource
	signal incident.Signal
}

// validateEntityFaults converts every untrusted field before any evidence or
// incident write. Only the live gRPC TLS state supplies tenant, agent and SVID;
// the request has no fields capable of selecting those authorities.
func validateEntityFaults(ctx context.Context, id crypto.SPIFFEID,
	raw []*agentv1.EntityFaultObservation) ([]entityFaultSubmission, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errEntityFaultPeer
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errEntityFaultPeer
	}
	validated := make([]entityFaultSubmission, 0, len(raw))
	seenIDs := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		if item == nil {
			return nil, entity.ErrInvalidClaim
		}
		fault, err := (entity.FaultObservation{
			ID: item.GetObservationId(),
			Source: entity.SourceKey{AgentID: id.AgentID,
				Kind: entity.SourceKind(item.GetSourceKind()), SourceRef: item.GetConfiguredRef()},
			Target: item.GetTargetAddress(), Kind: entity.FaultKind(item.GetKind()),
			ObservedAt: time.Unix(0, item.GetObservedUnixNanos()),
		}).Normalize(time.Now())
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenIDs[fault.ID]; duplicate {
			return nil, entity.ErrInvalidClaim
		}
		seenIDs[fault.ID] = struct{}{}
		source, err := incident.AuthenticatedSourceFromTLS(tlsInfo.State,
			string(fault.Source.Kind), fault.Source.SourceRef)
		if err != nil || source.TenantID() != id.TenantID || source.AgentID() != id.AgentID {
			return nil, errEntityFaultPeer
		}
		plane, title := entityFaultSignalShape(fault.Kind)
		validated = append(validated, entityFaultSubmission{source: source,
			signal: incident.Signal{TenantID: id.TenantID, Plane: plane,
				Kind: string(fault.Kind), Severity: incident.SeverityWarning,
				Title: title, Target: fault.Target, OccurredAt: fault.ObservedAt,
				Attributes: otel.EntityFaultAttributes(id.TenantID, id.AgentID, fault)},
		})
	}
	return validated, nil
}

func entityFaultSignalShape(kind entity.FaultKind) (plane, title string) {
	switch kind {
	case entity.FaultDevicePollFailed:
		return "device", "SNMP device poll failed"
	case entity.FaultFlowExporterSilent:
		return "flow", "Flow exporter silent"
	default:
		return "", "" // Normalize rejected it before this point.
	}
}

func (svc *service) persistEntityFaults(ctx context.Context, tenantID string,
	faults []entityFaultSubmission) (int, error) {
	if len(faults) == 0 {
		return 0, nil
	}
	if svc.entityFaultCorrelator == nil || svc.fence == nil {
		return 0, errors.New("entity fault: correlator or tenant writer fence unavailable")
	}
	for i := range faults {
		err := tenancy.FencedTenantWrite(ctx, svc.fence, tenantID,
			entity.ErrScopeMismatch, func(ctx context.Context) error {
				_, err := svc.entityFaultCorrelator.IngestAuthenticatedFault(ctx,
					faults[i].signal, faults[i].source,
					faults[i].signal.Attributes[entity.AttrFaultObservationID])
				return err
			})
		if err != nil {
			return i, err
		}
	}
	return len(faults), nil
}
