// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

// WithResolverDNSPressure configures the finite read-only detector at startup.
func (s *Server) WithResolverDNSPressure(policy dnstap.PressurePolicy) *Server {
	s.svc.resolverDNSPressure = &policy
	return s
}

func parseResolverDNSCapture(raw *agentv1.ResolverDNSCapture) (dnstap.ClosedCapture, [32]byte, error) {
	var empty dnstap.ClosedCapture
	var digest [32]byte
	if raw == nil || !dnstap.ValidSourceRef(raw.ConfiguredRef) || len(raw.ProtoReflect().GetUnknown()) != 0 ||
		len(raw.Intervals) == 0 || len(raw.Intervals) > dnstap.MaximumCaptureIntervals {
		return empty, digest, dnstap.ErrInvalidCapture
	}
	capture := dnstap.ClosedCapture{Frames: raw.ParsedFrames, Selected: raw.SelectedFrames}
	for _, item := range raw.Intervals {
		if item == nil || item.FromUnixNanos <= 0 || len(item.ProtoReflect().GetUnknown()) != 0 {
			return empty, digest, dnstap.ErrInvalidCapture
		}
		from := time.Unix(0, item.FromUnixNanos).UTC()
		capture.Intervals = append(capture.Intervals, dnstap.ResolverIntervalCounts{
			From: from, To: from.Add(dnstap.ResolverInterval), Responses: item.ClientResponses,
			NameErrors: item.NameErrors, ServerFailure: item.ServerFailures, Truncated: item.Truncated,
		})
	}
	if err := capture.Validate(time.Now()); err != nil {
		return empty, digest, err
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(raw)
	if err != nil || len(wire) > 16<<10 {
		return empty, digest, dnstap.ErrInvalidCapture
	}
	value := crypto.Hash(wire)
	if len(value) != len(digest) {
		return empty, digest, dnstap.ErrInvalidCapture
	}
	copy(digest[:], value)
	return capture, digest, nil
}

func (svc *service) submitResolverDNS(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	raw := req.GetResolverDns()
	capture, digest, err := parseResolverDNSCapture(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid reduced resolver capture")
	}
	if svc.entityFaultCorrelator == nil {
		return nil, status.Error(codes.Unavailable, "resolver evidence correlation is unavailable")
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil, status.Error(codes.Unauthenticated, "resolver evidence requires the verified TLS peer")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "resolver evidence requires the verified TLS peer")
	}
	source, err := incident.AuthenticatedSourceFromTLS(tlsInfo.State, string(entity.DNSResolver), raw.ConfiguredRef)
	if err != nil || source.TenantID() != id.TenantID || source.AgentID() != id.AgentID || source.CertificateSerial() != serial {
		return nil, status.Error(codes.Unauthenticated, "resolver evidence sender is unavailable")
	}
	if !svc.admitEntityEvidence(ctx, id.TenantID, len(capture.Intervals), proto.Size(req)) {
		return nil, status.Error(codes.ResourceExhausted, "tenant resolver evidence rate exceeded")
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(id.TenantID))
	policy := dnstap.PressurePolicy{Enabled: true, Rule: dnstap.DefaultPressureRule()}
	if svc.resolverDNSPressure != nil {
		policy = *svc.resolverDNSPressure
	}
	var retained store.ResolverDNSCaptureResult
	err = tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		var err error
		retained, err = store.NewEntityRegistry(svc.pool).CaptureResolverDNS(ctx, store.ResolverDNSCaptureInput{
			AgentID: id.AgentID, CertificateSerial: serial, SourceRef: raw.ConfiguredRef, Digest: digest, Capture: capture, Policy: policy,
		})
		return err
	})
	if err != nil {
		return nil, resolverDNSWriteError(err)
	}
	retained.Policy.Enabled = retained.Policy.Enabled && policy.Enabled
	submissions, err := resolverDNSPressureEvidence(source, retained, capture, digest)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "resolver pressure evaluation failed")
	}
	count, err := svc.persistEntityFaults(ctx, id.TenantID, submissions)
	if err != nil {
		return nil, resolverDNSWriteError(err)
	}
	if svc.log != nil {
		svc.log.Info("resolver capture processed", "tenant_id", id.TenantID, "intervals", len(capture.Intervals), "pressure_signals", count)
	}
	return &agentv1.SubmitEntityEvidenceResponse{ResolverDns: &agentv1.ResolverDNSCaptureReceipt{
		Intervals: uint32(len(capture.Intervals)), PressureSignals: uint32(count), EvidenceDigest: digest[:],
	}}, nil
}

func resolverDNSWriteError(err error) error {
	switch {
	case errors.Is(err, store.ErrEvidenceIdentityInactive), errors.Is(err, incident.ErrFaultIdentityInactive):
		return status.Error(codes.Unauthenticated, "resolver evidence identity is inactive")
	case errors.Is(err, store.ErrResolverDNSUnavailable), errors.Is(err, incident.ErrFaultSourceInactive):
		return status.Error(codes.FailedPrecondition, "current resolver source assignment is unavailable")
	case errors.Is(err, store.ErrResolverDNSConflict), errors.Is(err, incident.ErrFaultObservationConflict):
		return status.Error(codes.AlreadyExists, "resolver evidence has a conflicting interval")
	case errors.Is(err, store.ErrResolverDNSBudget):
		return status.Error(codes.ResourceExhausted, "tenant resolver evidence state admission exhausted")
	default:
		return status.Error(codes.Unavailable, "resolver evidence persistence failed")
	}
}

func resolverDNSPressureEvidence(source incident.AuthenticatedIdentitySource, retained store.ResolverDNSCaptureResult,
	capture dnstap.ClosedCapture, digest [32]byte) ([]entityFaultSubmission, error) {
	if !retained.Policy.Enabled {
		return nil, nil
	}
	rule := retained.Policy.Rule
	windows := append(append([]dnstap.ResolverIntervalCounts{}, retained.Previous...), capture.Intervals...)
	var out []entityFaultSubmission
	for i := max(1, len(retained.Previous)); i < len(windows); i++ {
		previous, current := windows[i-1], windows[i]
		if !previous.To.Equal(current.From) {
			continue
		}
		findings, err := dnstap.AssessResolverPressure(rule, previous, current)
		if err != nil {
			return nil, err
		}
		var active []dnstap.ResolverPressure
		if i > 1 && windows[i-2].To.Equal(previous.From) {
			active, err = dnstap.AssessResolverPressure(rule, windows[i-2], previous)
			if err != nil {
				return nil, err
			}
		}
		for _, finding := range findings {
			alreadyActive := false
			for _, prior := range active {
				alreadyActive = alreadyActive || prior.Kind == finding.Kind
			}
			if !alreadyActive {
				signal, err := resolverDNSPressureSignal(source, retained.Identity, finding, digest)
				if err != nil {
					return nil, err
				}
				out = append(out, entityFaultSubmission{source: source, signal: signal})
			}
		}
	}
	return out, nil
}

func resolverDNSPressureSignal(source incident.AuthenticatedIdentitySource, identity store.ResolverDNSIdentity,
	finding dnstap.ResolverPressure, digest [32]byte) (incident.Signal, error) {
	at := finding.Current.To
	fields := []string{"probectl:resolver-dns-pressure:v1", source.TenantID(), identity.AgentID, identity.SourceRef,
		identity.DeviceID, identity.SourceAssignedAt.UTC().Format(time.RFC3339Nano), identity.AgentAssignedAt.UTC().Format(time.RFC3339Nano),
		at.UTC().Format(time.RFC3339Nano), string(finding.Kind)}
	raw := crypto.Hash([]byte(strings.Join(fields, "\x00")))
	if len(raw) < 16 {
		return incident.Signal{}, dnstap.ErrInvalidCapture
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	observation, err := uuid.FromBytes(raw[:16])
	if err != nil {
		return incident.Signal{}, err
	}
	return incident.Signal{
		TenantID: source.TenantID(), Plane: "device", Kind: "dns.resolver." + string(finding.Kind),
		Severity: incident.SeverityWarning, Title: "Sustained resolver response pressure",
		Summary: "Two adjacent resolver capture windows crossed the observed response and error-share floors.",
		Target:  "resolver:" + identity.DeviceID, OccurredAt: at,
		Attributes: map[string]string{
			entity.AttrFaultObservationID: observation.String(), "dns.resolver.capture_sha256": hex.EncodeToString(digest[:]),
			"detector.confidence":   "60",
			"dns.resolver.coverage": "closed_file_captured_responses", "dns.resolver.window_from": finding.Previous.From.UTC().Format(time.RFC3339Nano),
			"dns.resolver.window_to":        at.UTC().Format(time.RFC3339Nano),
			"dns.resolver.client_responses": strconv.FormatUint(uint64(finding.Current.Responses), 10),
			"dns.resolver.name_errors":      strconv.FormatUint(uint64(finding.Current.NameErrors), 10),
			"dns.resolver.server_failures":  strconv.FormatUint(uint64(finding.Current.ServerFailure), 10),
			"dns.resolver.truncated":        strconv.FormatUint(uint64(finding.Current.Truncated), 10),
		},
	}, nil
}
