// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type clientReportVerdict struct {
	IncidentID    string
	From, To      time.Time
	Verdict       incident.FaultVerdict
	PackageID     string
	PackageDigest string
	SignedPackage json.RawMessage
	SourceDigest  string
	publication   incidentEvidenceFinalizer
}

// Use the deterministic classifier and existing portable evidence contract.
// No model/RCA call is made, so this does not acquire AI authority or egress.
// Every retained finalizer checks the original selectors and current source
// authority again after the whole report has been rendered and signed.
func (s *Server) captureClientReportVerdicts(ctx context.Context, actor *auth.Principal, capture *clientReportCapture, memory *int64) ([]clientReportVerdict, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || actor == nil || capture == nil || capture.Events == nil || bound.String() != actor.TenantID || capture.TenantID != actor.TenantID {
		return nil, entity.ErrScopeMismatch
	}
	if len(capture.Events.Incidents) > 0 && len(s.evidenceSigningKey) == 0 {
		return nil, apierror.Unavailable("monthly incident evidence signing is not configured")
	}
	if memory == nil || *memory <= 0 || int64(len(capture.Events.Incidents)) > *memory/4096 {
		return nil, store.ErrClientReportBudget
	}
	remaining := *memory - int64(len(capture.Events.Incidents))*4096
	results := make([]clientReportVerdict, 0, len(capture.Events.Incidents))
	for _, item := range capture.Events.Incidents {
		if item.TenantID != actor.TenantID {
			return nil, entity.ErrScopeMismatch
		}
		if remaining < 1<<17 {
			return nil, store.ErrClientReportBudget
		}
		var original *store.IncidentImpactInputs
		var retained *incidentVerdictSnapshot
		var publication incidentEvidenceFinalizer
		verdict, err := s.computeRetainedIncidentVerdict(ctx, actor, item.ID, capture.From, capture.To, remaining/2, &original, &publication, &retained)
		if err != nil {
			return nil, err
		}
		if retained == nil || publication == nil {
			return nil, apierror.Unavailable("monthly incident original-source validation is unavailable")
		}
		if err := requireImpactIncidentHeader(actor.TenantID, &item, original); err != nil {
			return nil, err
		}
		digest, err := hashFlowRoleInputs(ctx, nil, original, remaining/8)
		if err != nil {
			return nil, err
		}
		if hex.EncodeToString(digest) != capture.Events.IncidentLineage[item.ID] {
			return nil, apierror.Unavailable("monthly incident membership changed during capture; retry")
		}

		for _, source := range retained.tests {
			capture.sourceKeys = append(capture.sourceKeys, store.ReportSourceKey{ContextID: source.ContextID, AgentID: source.AgentID, Kind: "path_agent", Ref: source.TestID})
		}
		for _, source := range retained.sources {
			if source.Current {
				capture.sourceKeys = append(capture.sourceKeys, store.ReportSourceKey{ContextID: source.ContextID, AgentID: source.AgentID, Kind: "device_target", Ref: source.ConfiguredRef})
			}
		}
		for _, role := range retained.roles {
			refs := []string{}
			if role.SNMP != nil {
				refs = append(refs, role.SNMP.SourceID)
				if role.SNMP.PrefixSourceID != "" {
					refs = append(refs, role.SNMP.PrefixSourceID)
				}
				for _, binding := range role.SNMP.Bindings {
					refs = append(refs, binding.SourceID)
				}
			}
			for _, peer := range role.Peers {
				refs = append(refs, peer.SourceID)
			}
			for _, id := range refs {
				if id == "" {
					continue
				}
				id, ok := strings.CutPrefix(id, "evidence/")
				if !ok {
					return nil, entity.ErrInvalidClaim
				}
				capture.evidenceRefs = append(capture.evidenceRefs, store.ReportEvidenceRef{ContextID: role.Scope.ContextID, ID: id})
			}
		}
		for _, session := range retained.peerSessions {
			if session.SourceCurrent {
				capture.sourceKeys = append(capture.sourceKeys, store.ReportSourceKey{ContextID: session.ContextID, AgentID: session.AgentID, Kind: "bmp_peer", Ref: session.ConfiguredRef})
			}
		}
		for _, route := range retained.routes {
			if route.Route == nil {
				continue
			}
			var key store.ReportSourceKey
			err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				key, err = (store.BGPRouting{}).ReportBaseSourceKeyInScope(ctx, sc, route.Route.Source, store.BGPRoutingBudget{MemoryBytes: remaining / 16, WorkUnits: remaining / 16, StateBytes: remaining / 16})
				return err
			})
			if err != nil {
				return nil, err
			}
			capture.sourceKeys = append(capture.sourceKeys, key)
		}
		pol := incidentEvidenceTenantPolicy(redactionPolicy(s.cfg), actor.TenantID)
		redacted := redactIncidentForShare(item, pol, actor.TenantID)
		// Monthly headers do not repeat the incident's signal bodies. Preserve
		// that omission explicitly rather than claiming a complete signal set.
		redacted.SignalsTruncated = redacted.SignalCount > len(redacted.Signals)
		publicVerdict, err := redactIncidentVerdict(verdict, pol, actor.TenantID)
		if err != nil {
			return nil, err
		}
		manifest, attachments, err := evidence.Build(evidence.BuildInput{TenantID: actor.TenantID, Incident: redacted, CreatedAt: time.Now().UTC(), Verdict: &publicVerdict})
		if err != nil {
			return nil, err
		}
		signed, err := evidence.Sign(manifest, attachments, s.evidenceSigningKey)
		if err != nil {
			return nil, err
		}
		cost, err := clientReportVerdictRetainedBytes(retained, verdict, len(signed))
		if err != nil {
			return nil, err
		}
		if cost > remaining {
			return nil, store.ErrClientReportBudget
		}
		remaining -= cost
		if err := publication(ctx); err != nil {
			return nil, err
		}
		results = append(results, clientReportVerdict{IncidentID: item.ID, From: capture.From, To: capture.To, Verdict: publicVerdict, PackageID: manifest.PackageID,
			PackageDigest: hex.EncodeToString(crypto.Hash(signed)), SignedPackage: signed, SourceDigest: retained.digest, publication: publication})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*memory = remaining
	return results, nil
}

func clientReportVerdictRetainedBytes(snapshot *incidentVerdictSnapshot, result incident.FaultVerdict, signedBytes int) (int64, error) {
	// Private classifier wrappers share these original documents. Explicitly
	// include every family: marshaling the private snapshot itself would yield
	// {} and undercount complete outcomes, paths or routing payloads.
	body, err := json.Marshal([]any{snapshot.inputs, snapshot.sources, snapshot.tests, snapshot.roles, snapshot.states, snapshot.outcomes, snapshot.peerSessions, snapshot.pathBindings, snapshot.pathGroups, snapshot.routes, result})
	if err != nil {
		return 0, err
	}
	wrappers := int64(len(snapshot.evidence.interfaces))*4096 + int64(len(snapshot.evidence.tests))*2048 + int64(len(snapshot.evidence.paths))*2048 + int64(len(snapshot.evidence.routes))*4096
	return 4096 + 8*int64(len(body)) + 8*int64(signedBytes) + wrappers, nil
}
