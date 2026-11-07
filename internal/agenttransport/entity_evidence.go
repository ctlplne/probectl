// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Both record count and encoded bytes consume the existing tenant budgets.
// Nil admission or an exhausted bucket refuses before any evidence write.
func (svc *service) admitEntityEvidence(ctx context.Context, tenant string, total, bytes int) bool {
	return svc != nil && svc.fairness != nil && tenant != "" && total > 0 && bytes > 0 &&
		svc.fairness.AdmitN(ctx, tenant, fairness.MeterEntityEvidence, int64(total)) &&
		svc.fairness.AdmitN(ctx, tenant, fairness.MeterEntityEvidenceBytes, int64(bytes))
}

// SubmitEntityEvidence is D-179's restricted writer. The request contains no
// tenant, agent, context or entity ID. The evidence-only mTLS identity selects
// tenant and agent; active operator assignments select context and canonical
// anchor under FORCE RLS. An unanchored flow/BMP source requires unique,
// current, same-context SNMP support; other unanchored sources stay unresolved.
func (svc *service) SubmitEntityEvidence(ctx context.Context, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	outcome := "rejected"
	defer func() {
		if counter := svc.entityEvidenceBatches[outcome]; counter != nil {
			counter.Inc()
		}
	}()
	id, err := svc.authenticateEntityEvidence(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "evidence identity is not valid")
	}
	if svc.pool == nil || svc.fence == nil {
		return nil, status.Error(codes.Unavailable, "entity evidence store is not configured")
	}
	leaf, err := peerLeafFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "evidence certificate is missing")
	}
	identities := store.NewAgentIdentities(svc.pool)
	known, err := identities.KnownIssuedIdentity(ctx, id.TenantID, id.AgentID,
		id.String(), leaf.SerialNumber.Text(16))
	if err != nil {
		return nil, status.Error(codes.Unavailable, "evidence identity lookup failed")
	}
	if !known {
		return nil, status.Error(codes.Unauthenticated, "evidence identity was not issued to this agent")
	}
	revoked, err := identities.IsAgentRevoked(ctx, id.TenantID, id.AgentID)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "evidence revocation lookup failed")
	}
	if revoked {
		return nil, status.Error(codes.PermissionDenied, "evidence identity was revoked")
	}
	if req.GetFlowRouting() != nil {
		response, err := svc.submitFlowRoutingEvidence(ctx, id, req)
		if err == nil {
			outcome = "accepted"
		}
		return response, err
	}
	if req.GetRoutingPeerUp() != nil || req.GetRoutingMessage() != nil {
		response, accepted, err := svc.submitRoutingEvidence(ctx, id, leaf.SerialNumber.Text(16), req)
		if accepted {
			outcome = "accepted"
		}
		return response, err
	}

	items := req.GetObservations()
	rawFaults := req.GetFaults()
	total := len(items) + len(rawFaults)
	if total == 0 || total > 64 {
		return nil, status.Error(codes.InvalidArgument, "evidence batch must contain 1–64 observations and faults combined")
	}
	requestBytes := proto.Size(req)
	for _, item := range items {
		if item != nil && item.SnmpInterfacePrefixes != nil && requestBytes > entity.MaxSNMPInterfacePrefixWireBytes {
			return nil, status.Error(codes.ResourceExhausted, "complete prefix evidence exceeds request byte admission")
		}
	}
	if len(rawFaults) > 0 && svc.entityFaultCorrelator == nil {
		return nil, status.Error(codes.Unavailable, "entity fault correlation is not configured")
	}
	if !svc.admitEntityEvidence(ctx, id.TenantID, total, requestBytes) {
		return nil, status.Error(codes.ResourceExhausted, "tenant entity evidence rate exceeded")
	}
	faults, err := validateEntityFaults(ctx, id, rawFaults)
	if err != nil {
		if errors.Is(err, errEntityFaultPeer) {
			return nil, status.Error(codes.Unauthenticated, "verified evidence sender is required")
		}
		return nil, status.Error(codes.InvalidArgument, "invalid entity fault observation")
	}
	observations := make([]entity.Observation, 0, len(items))
	for _, item := range items {
		if item == nil {
			return nil, status.Error(codes.InvalidArgument, "evidence observation is missing")
		}
		var addresses []netip.Addr
		if item.AgentAddresses != nil {
			addresses, err = entity.ParseAgentAddressSnapshot(item.AgentAddresses.Addresses)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, "invalid agent address snapshot")
			}
		}
		prefixes, err := parseSNMPPrefixEvidence(item.SnmpInterfacePrefixes)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid complete SNMP interface prefix snapshot")
		}
		observations = append(observations, entity.Observation{
			ID: item.GetObservationId(),
			Source: entity.SourceKey{
				AgentID: id.AgentID, Kind: entity.SourceKind(item.GetSourceKind()),
				SourceRef: item.GetConfiguredRef(),
			},
			Alias: entity.AliasKey{
				Kind: entity.AliasKind(item.GetAliasKind()), Value: item.GetAliasValue(),
			},
			SourceRef: item.GetSourceRef(), OriginSerial: item.GetOriginSerial(),
			InterfaceName:         item.GetInterfaceName(),
			InterfaceDescription:  item.GetInterfaceDescription(),
			SystemDescription:     item.GetSystemDescription(),
			SystemName:            item.SystemName,
			AgentAddresses:        addresses,
			SNMPInterfacePrefixes: prefixes,
			NeighborProtocol:      item.GetNeighborProtocol(),
			NeighborLocalIfIndex:  item.GetNeighborLocalIfIndex(),
			NeighborLocalPortID:   item.GetNeighborLocalPortId(),
			NeighborRemotePortID:  item.GetNeighborRemotePortId(),
			NeighborChassisID:     item.GetNeighborChassisId(),
			NeighborDeviceName:    item.GetNeighborDeviceName(),
			NeighborAddress:       item.GetNeighborManagementAddress(),
			ObservedAt:            time.Unix(0, item.GetObservedUnixNanos()),
		})
	}
	var accepted, unresolved int
	if len(observations) > 0 {
		err = tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID,
			entity.ErrScopeMismatch, func(ctx context.Context) error {
				var writeErr error
				accepted, unresolved, writeErr = store.NewEntityRegistry(svc.pool).
					WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)),
						id.AgentID, leaf.SerialNumber.Text(16), observations)
				return writeErr
			})
		if err != nil {
			switch {
			case errors.Is(err, store.ErrEvidenceIdentityInactive):
				return nil, status.Error(codes.Unauthenticated, "evidence identity is not active")
			case errors.Is(err, entity.ErrInvalidClaim), errors.Is(err, entity.ErrInvalidAlias),
				errors.Is(err, entity.ErrInvalidSource):
				return nil, status.Error(codes.InvalidArgument, "invalid entity evidence observation")
			case errors.Is(err, entity.ErrConflictingEvidence):
				return nil, status.Error(codes.AlreadyExists, "observation ID was reused for different evidence")
			default:
				return nil, status.Error(codes.Unavailable, "entity evidence write failed")
			}
		}
	}
	faultsPersisted, err := svc.persistEntityFaults(ctx, id.TenantID, faults)
	if err != nil {
		if errors.Is(err, incident.ErrFaultIdentityInactive) {
			return nil, status.Error(codes.Unauthenticated, "fault sender identity is not active")
		}
		if errors.Is(err, incident.ErrFaultSourceInactive) {
			return nil, status.Error(codes.PermissionDenied, "fault source assignment is not active")
		}
		if errors.Is(err, incident.ErrFaultObservationConflict) {
			return nil, status.Error(codes.AlreadyExists, "fault observation ID was reused for different evidence")
		}
		return nil, status.Error(codes.Unavailable, "entity fault persistence failed")
	}
	if svc.log != nil {
		svc.log.Info("entity evidence batch processed", "tenant_id", id.TenantID,
			"agent_id", id.AgentID, "accepted", accepted, "unresolved", unresolved,
			"faults_persisted", faultsPersisted)
	}
	if counter := svc.entityEvidenceObservations["accepted"]; counter != nil {
		counter.Add(uint64(accepted))
	}
	if counter := svc.entityEvidenceObservations["unresolved"]; counter != nil {
		counter.Add(uint64(unresolved))
	}
	switch {
	case accepted == 0 && faultsPersisted == 0:
		outcome = "unresolved"
	case unresolved > 0:
		outcome = "partial"
	default:
		outcome = "accepted"
	}
	return &agentv1.SubmitEntityEvidenceResponse{
		Accepted: uint32(accepted), Unresolved: uint32(unresolved),
		FaultsPersisted: uint32(faultsPersisted),
	}, nil
}

func parseSNMPPrefixEvidence(snapshot *agentv1.SnmpInterfacePrefixSnapshot) ([]entity.SNMPInterfacePrefix, error) {
	if snapshot == nil {
		return nil, nil
	}
	rows := []entity.SNMPInterfacePrefix{}
	for _, row := range snapshot.Prefixes {
		if row == nil {
			return nil, entity.ErrInvalidClaim
		}
		prefix, err := netip.ParsePrefix(row.Prefix)
		if err != nil {
			return nil, entity.ErrInvalidClaim
		}
		rows = append(rows, entity.SNMPInterfacePrefix{IfIndex: row.IfIndex, Prefix: prefix, OnLink: row.OnLink})
	}
	return entity.NormalizeSNMPInterfacePrefixes(rows)
}
