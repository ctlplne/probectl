// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"encoding/hex"
	"time"
)

// ProbeOutcome is a completed configured-test result on the evidence-only
// sender-authenticated plane. It proves an observed test outcome, never packet
// loss, an upstream root cause, a tenant, or current source authority. Raw
// errors, response bodies, targets and secret-bearing parameters are excluded.
type ProbeOutcome struct {
	Version        int                `json:"version"`
	DefinitionHash string             `json:"definition_hash"`
	CanaryType     string             `json:"canary_type"`
	StartedAt      time.Time          `json:"started_at"`
	CompletedAt    time.Time          `json:"completed_at"`
	Success        bool               `json:"success"`
	Canceled       bool               `json:"canceled"`
	HTTPResponse   *ProbeHTTPResponse `json:"http_response,omitempty"`
}

// ProbeHTTPResponse contains primary request facts, never raw response content.
type ProbeHTTPResponse struct {
	StatusCode  int  `json:"status_code"`
	TLSVerified bool `json:"tls_verified"`
	SameOrigin  bool `json:"same_origin"`
}

func normalizeProbeOutcome(o Observation) (*ProbeOutcome, error) {
	if o.Outcome == nil {
		return nil, nil
	}
	if o.ICMP != nil || o.Source.Kind != PathAgent || o.Alias.Kind != ConfiguredTestAlias || o.Alias.Value != o.Source.SourceRef || o.SourceRef != "probe:configured-test" {
		return nil, ErrInvalidClaim
	}
	m := *o.Outcome
	digest, err := hex.DecodeString(m.DefinitionHash)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != m.DefinitionHash || m.CanaryType == "" || m.CanaryType == "icmp" || len(m.CanaryType) > 128 {
		return nil, ErrInvalidClaim
	}
	for _, r := range m.CanaryType {
		allowed := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-'
		if !allowed {
			return nil, ErrInvalidClaim
		}
	}
	switch m.Version {
	case 1:
		if m.HTTPResponse != nil {
			return nil, ErrInvalidClaim
		}
	case 2:
		if m.CanaryType != "http" || m.HTTPResponse == nil || m.HTTPResponse.StatusCode < 100 || m.HTTPResponse.StatusCode > 999 {
			return nil, ErrInvalidClaim
		}
		response := *m.HTTPResponse
		m.HTTPResponse = &response
	default:
		return nil, ErrInvalidClaim
	}
	if m.StartedAt.IsZero() || m.CompletedAt.IsZero() || m.CompletedAt.Before(m.StartedAt) || !m.CompletedAt.UTC().Truncate(time.Microsecond).Equal(o.ObservedAt.UTC().Truncate(time.Microsecond)) {
		return nil, ErrInvalidClaim
	}
	m.StartedAt = m.StartedAt.UTC().Truncate(time.Microsecond)
	m.CompletedAt = m.CompletedAt.UTC().Truncate(time.Microsecond)
	return &m, nil
}
