// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"net/netip"
	"time"
)

// ServiceClassification is a range attribution, not application identification.
// Empty service/provider/region means unknown. Sources retains every original
// candidate and source clock, including conflicts, for capture-time provenance.
type ServiceClassification struct {
	Service  string               `json:"service"`
	Region   string               `json:"region"`
	Provider string               `json:"provider"`
	Status   string               `json:"status"`
	Sources  []ServiceRangeStatus `json:"sources"`
}

// LocalServiceRanges reads only the immutable, process-local source index. It
// bypasses both enrichment caches and never invokes a DNS or HTTP source. This
// keeps original source expiry authoritative even on an asynchronous cache hit.
func (en *Enricher) LocalServiceRanges(ctx context.Context, ip string, at time.Time) []ServiceRangeStatus {
	addr, err := netip.ParseAddr(ip)
	if en == nil || err != nil || ctx.Err() != nil || at.IsZero() {
		return nil
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	var result []ServiceRangeStatus
	for _, managed := range en.sources {
		source, ok := managed.src.(*ServiceRanges)
		if !ok {
			continue
		}
		if len(source.datasets) == 0 {
			result = append(result, ServiceRangeStatus{Publisher: "unavailable", Status: "unavailable", Matches: []ServiceRangeMatch{}})
			continue
		}
		result = append(result, source.lookup(addr, at, managed.health.Enabled)...)
	}
	return result
}

type serviceCandidate struct {
	provider string
	match    ServiceRangeMatch
	bits     int
}

// ClassifyServiceRanges selects a unique most-specific published attribution.
// Documented supersets do not mask their specific services: AMAZON is AWS's
// superset, S3 excludes EC2 at the same address, and cloud.json specializes
// goog.json. Unresolved equal-specificity services remain ambiguous, never an
// arbitrary winner. Region conflicts retain a known service and unknown region.
func ClassifyServiceRanges(sources []ServiceRangeStatus, at time.Time) ServiceClassification {
	out := ServiceClassification{Status: "unknown", Sources: sources}
	var candidates []serviceCandidate
	awsSpecific, s3, googleCloud := false, false, false
	for _, source := range sources {
		if source.Status != "matched" || at.Before(source.FetchedAt) || !at.Before(source.ValidUntil) {
			continue
		}
		for _, match := range source.Matches {
			prefix, err := netip.ParsePrefix(match.Prefix)
			if err != nil || !validServiceRangeLabel(match.Service) {
				continue
			}
			candidates = append(candidates, serviceCandidate{source.Publisher, match, prefix.Bits()})
			awsSpecific = awsSpecific || source.Publisher == "aws" && match.Service != "AMAZON"
			s3 = s3 || source.Publisher == "aws" && match.Service == "S3"
			googleCloud = googleCloud || source.Publisher == "google_cloud"
		}
	}
	best := -1
	for _, candidate := range candidates {
		if serviceCandidateIsSuperset(candidate, awsSpecific, s3, googleCloud) {
			continue
		}
		if candidate.bits > best {
			best = candidate.bits
			out.Service, out.Provider, out.Region, out.Status = candidate.match.Service, candidate.provider, candidate.match.Region, "known"
			continue
		}
		if candidate.bits != best {
			continue
		}
		if candidate.provider != out.Provider || candidate.match.Service != out.Service {
			out.Status = "ambiguous"
		} else if candidate.match.Region != out.Region {
			out.Region = ""
		}
	}
	if out.Status == "ambiguous" {
		out.Service, out.Provider, out.Region = "", "", ""
	}
	return out
}

func serviceCandidateIsSuperset(candidate serviceCandidate, awsSpecific, s3, googleCloud bool) bool {
	return candidate.provider == "aws" && ((candidate.match.Service == "AMAZON" && awsSpecific) || (candidate.match.Service == "EC2" && s3)) ||
		candidate.provider == "google" && googleCloud
}
