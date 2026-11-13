// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"net/netip"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
)

// Current transit intent alone is insufficient. Bind the original physical
// peer event to a complete observed prefix and an owned canonical interface,
// then require independent contemporaneous loss and healthy local coverage.
func classifyIncidentCarrier(ctx context.Context, input incidentVerdictEvidence, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	proven := false
	for _, item := range input.interfaces {
		if (!item.direct && !item.incidentRouter) || !item.source.Current || item.role.Role != interfaceRoleTransit || !item.role.SNMPCurrent || !item.role.PrefixCurrent {
			continue
		}
		if int64(len(item.peerReads)) > *remaining/128 {
			return false, store.ErrIncidentImpactBudget
		}
		*remaining -= int64(len(item.peerReads)) * 128
		conflicts := incidentCarrierPeerConflicts(item.peerReads, input)
		for _, read := range item.peerReads {
			if !verdictObservationInWindow(read.ObservedAt, input) {
				continue
			}
			citation, associated, err := incidentCarrierPeerCitation(ctx, item, read, remaining)
			if err != nil {
				return false, err
			}
			if !associated {
				hypothesis.Missing = append(hypothesis.Missing, "original_peer_current_declared_asn_and_handoff_coverage")
				continue
			}
			fresh, err := admitVerdictOriginal(citation, seen, remaining)
			if err != nil {
				return false, err
			}
			if !fresh {
				continue
			}
			if read.Session.State == "up" {
				citation.Reason = "original_carrier_peer_up"
				hypothesis.Against = append(hypothesis.Against, citation)
				continue
			}
			// Administrative Cease, monitoring withdrawal and an unspecified
			// connection close cannot prove an unplanned carrier failure.
			if !incidentPeerHoldTimerExpired(read) {
				hypothesis.Missing = append(hypothesis.Missing, "unplanned_original_physical_neighbor_failure")
				continue
			}
			citation.Reason = "original_carrier_neighbor_hold_timer_expired"
			hypothesis.For = append(hypothesis.For, citation)
			handoff, err := incidentCarrierHandoffState(ctx, item, input, read.ObservedAt, seen, remaining, hypothesis)
			if err != nil {
				return false, err
			}
			backbone, err := incidentCarrierLocalCoverage(ctx, input, item, read.ObservedAt, seen, remaining, hypothesis)
			if err != nil {
				return false, err
			}
			loss, err := incidentCarrierNetworkLoss(ctx, input, item, read.ObservedAt, seen, remaining, hypothesis)
			if err != nil {
				return false, err
			}
			if handoff && backbone && loss && !conflicts[incidentCarrierPeerKey{read.Session.PeerAddress, read.Session.PeerASN}] {
				proven = true
			}
		}
	}
	if proven {
		hypothesis.Confidence = "corroborated"
	} else {
		hypothesis.Missing = append(hypothesis.Missing, "original_carrier_failure_and_current_asn_handoff")
	}
	return proven, ctx.Err()
}

func incidentCarrierPeerCitation(ctx context.Context, item incidentVerdictInterface, read store.IncidentPeerSessionMeasurement, remaining *int64) (incident.VerdictCitation, bool, error) {
	none := incident.VerdictCitation{}
	in := item.roleInputs
	now := time.Now().UTC()
	if !read.SourceCurrent || read.Session == nil || read.ValidUntil == nil || !read.ValidUntil.After(now) || in.SNMP == nil || in.SNMP.Prefixes == nil ||
		!slices.Contains(in.Policy.Definition.ProviderASNs, read.Session.PeerASN) || in.Policy.UpdatedAt.After(read.ObservedAt) || in.Override != nil && in.Override.UpdatedAt.After(read.ObservedAt) || in.SNMP.PrefixClock.ObservedAt.After(read.ObservedAt) {
		return none, false, nil
	}
	budget := interfaceRoleBudget{MemoryBytes: *remaining, WorkUnits: *remaining}
	prefixes, bindings, err := interfaceRoleAssociationInputs(ctx, in, &budget)
	if err != nil {
		return none, false, err
	}
	address, err := netip.ParseAddr(read.Session.PeerAddress)
	if err != nil {
		return none, false, err
	}
	peer := interfaceRoleUnboundPeer{Scope: in.Scope, RouterID: in.RouterID, SourceID: "evidence/" + read.EvidenceID, Address: address, ASN: read.Session.PeerASN, SourceActive: true,
		Clock: interfaceRoleClock{ObservedAt: read.ObservedAt, ValidUntil: *read.ValidUntil}}
	association, err := associateInterfaceRolePeerAdmitted(ctx, in.Scope, in.RouterID, now, peer, prefixes, bindings, &budget)
	*remaining = budget.MemoryBytes
	if err != nil {
		return none, false, err
	}
	if association.Peer.InterfaceID != item.source.EntityID {
		return none, false, nil
	}
	// A later binding cannot retrospectively place this event at a hand-off.
	for _, binding := range in.SNMP.Bindings {
		if binding.InterfaceID == association.Peer.InterfaceID && binding.ObservedAt.After(read.ObservedAt) {
			return none, false, nil
		}
	}
	return incident.VerdictCitation{ContextID: read.ContextID, EntityID: read.RouterID, EvidenceID: read.EvidenceID, AgentID: read.AgentID, Digest: hex.EncodeToString(read.CaptureDigest[:]), ObservedAt: read.ObservedAt,
		PeerASN: read.Session.PeerASN, HandoffInterfaceID: association.Peer.InterfaceID}, true, nil
}

func incidentPeerHoldTimerExpired(read store.IncidentPeerSessionMeasurement) bool {
	m := read.Session
	return m != nil && m.State == "down" && m.DownReason != nil && (*m.DownReason == 1 || *m.DownReason == 3) && m.NotificationCode != nil && *m.NotificationCode == 4 && m.NotificationSubcode != nil && *m.NotificationSubcode == 0
}

func incidentCarrierHandoffState(ctx context.Context, item incidentVerdictInterface, input incidentVerdictEvidence, after time.Time, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	healthy, unavailable := false, false
	for _, read := range item.reads {
		if read.ObservedAt.Before(after) || !verdictObservationInWindow(read.ObservedAt, input) {
			continue
		}
		if !read.Available || !read.OriginalSenderValid || read.ObservedAt.Before(item.source.CurrentSince) || read.State == nil || read.State.AdminStatus == nil || read.State.OperStatus == nil {
			unavailable = true
			continue
		}
		if *read.State.AdminStatus != 1 || *read.State.OperStatus != 1 {
			unavailable = true
			continue
		}
		citation := interfaceVerdictCitation(read, "original_owned_carrier_handoff_admin_up_oper_up")
		fresh, err := admitVerdictOriginal(citation, seen, remaining)
		if err != nil {
			return false, err
		}
		if fresh {
			hypothesis.For = append(hypothesis.For, citation)
		}
		healthy = true
	}
	if !healthy || unavailable {
		hypothesis.Missing = append(hypothesis.Missing, "contemporaneous_original_enabled_healthy_handoff")
		return false, nil
	}
	return true, ctx.Err()
}

func incidentCarrierLocalCoverage(ctx context.Context, input incidentVerdictEvidence, handoff incidentVerdictInterface, after time.Time, seen map[string]incident.VerdictCitation, remaining *int64, hypothesis *incident.VerdictHypothesis) (bool, error) {
	healthy, conflicting, unavailable := false, false, false
	for _, item := range input.interfaces {
		if item.source.ContextID != handoff.source.ContextID || item.source.RouterID != handoff.source.RouterID || item.source.EntityID == handoff.source.EntityID || (!item.direct && !item.incidentRouter) || !item.source.Current || !item.role.SNMPCurrent || item.role.Role != interfaceRoleBackbone {
			continue
		}
		observed := false
		for _, read := range item.reads {
			if read.ObservedAt.Before(after) || !verdictObservationInWindow(read.ObservedAt, input) {
				continue
			}
			observed = true
			if !read.Available || !read.OriginalSenderValid || read.ObservedAt.Before(item.source.CurrentSince) || read.State == nil || read.State.AdminStatus == nil || read.State.OperStatus == nil {
				unavailable = true
				continue
			}
			admin, oper := *read.State.AdminStatus, *read.State.OperStatus
			if admin == 1 && (oper == 2 || oper == 7) {
				conflicting = true
				continue
			}
			if admin != 1 || oper != 1 {
				unavailable = true
				continue
			}
			citation := interfaceVerdictCitation(read, "original_healthy_owned_local_backbone")
			if _, err := admitVerdictOriginal(citation, seen, remaining); err != nil {
				return false, err
			}
			hypothesis.For = append(hypothesis.For, citation)
			healthy = true
		}
		if !observed {
			unavailable = true
		}
	}
	if !healthy || conflicting || unavailable {
		hypothesis.Missing = append(hypothesis.Missing, "contemporaneous_original_healthy_local_network")
		return false, nil
	}
	return true, ctx.Err()
}

type incidentCarrierPeerKey struct {
	address string
	asn     uint32
}

func incidentCarrierPeerConflicts(reads []store.IncidentPeerSessionMeasurement, input incidentVerdictEvidence) map[incidentCarrierPeerKey]bool {
	out := map[incidentCarrierPeerKey]bool{}
	for _, read := range reads {
		if read.SourceCurrent && read.Session != nil && verdictObservationInWindow(read.ObservedAt, input) && (read.Session.State == "up" || read.Session.State == "monitoring_withdrawn") {
			out[incidentCarrierPeerKey{read.Session.PeerAddress, read.Session.PeerASN}] = true
		}
	}
	return out
}
