// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package remediation

import (
	"context"
	"net/netip"
	"time"
)

// RoutingTransferDryRunEvidence is supplied by the control plane after
// resolving current owned flow, route and configuration authority.
// ArchiveContent is used for compilation and is never part of the response.
type RoutingTransferDryRunEvidence struct {
	TenantID, ContextID, RouterID, ArchiveID, ArchiveDigest string
	ArchiveAgentID, ArchiveSourceRef                        string
	ArchiveContent                                          string
	ArchiveObservedAt                                       time.Time
	CandidatePeer                                           netip.Addr
	CandidateASN                                            uint32
	ExactPrefix                                             netip.Prefix
	LocalPreference                                         uint32
	MaxConfigBytes                                          int64
	EstimateDigest                                          string
	SourceValidUntil                                        time.Time
	MovedPeakBPS, CandidatePeakBPS, CandidateLimitBPS       string
}

type RoutingTransferDryRun struct {
	ContextID              string    `json:"context_id,omitempty"`
	RouterID               string    `json:"router_id"`
	ArchiveID              string    `json:"archive_id"`
	ArchiveDigest          string    `json:"archive_digest"`
	ArchiveAgentID         string    `json:"archive_agent_id,omitempty"`
	ArchiveSourceRef       string    `json:"archive_source_ref,omitempty"`
	ArchiveObservedAt      time.Time `json:"archive_observed_at"`
	CandidatePeer          string    `json:"candidate_peer"`
	CandidateASN           uint32    `json:"candidate_asn"`
	ExactPrefix            string    `json:"exact_prefix"`
	CurrentInboundPolicy   string    `json:"current_inbound_policy"`
	ProposedInboundPolicy  string    `json:"proposed_inbound_policy"`
	DefaultLocalPreference uint32    `json:"default_local_preference"`
	WeightVerification     bool      `json:"requires_weight_verification"`
	EstimateDigest         string    `json:"estimate_digest"`
	SourceValidUntil       time.Time `json:"source_valid_until"`
	PreviewFingerprint     string    `json:"preview_fingerprint"`
	AddressCountUpperBound string    `json:"address_count_upper_bound"`
	AddressLimit           string    `json:"address_limit"`
	MovedPeakBPS           string    `json:"moved_peak_bps"`
	CandidatePeakBPS       string    `json:"candidate_peak_bps"`
	CandidateLimitBPS      string    `json:"candidate_limit_bps"`
	Configure              []string  `json:"configure"`
	Withdraw               []string  `json:"withdraw"`
}

type RoutingTransferDryRunner interface {
	PreviewRoutingTransfer(context.Context, string, RoutingTransferDryRunEvidence) (RoutingTransferDryRun, error)
}
