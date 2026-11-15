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

type serviceSupersets struct {
	awsSpecific, s3, googleCloud, azureSpecific, zoomSpecific, m365Specific, saasSpecific bool
}

// ClassifyServiceRanges selects a unique most-specific published attribution.
// Documented supersets do not mask their specific services: AMAZON is AWS's
// superset, S3 excludes EC2 at the same address, and cloud.json specializes
// goog.json. Unresolved equal-specificity services remain ambiguous, never an
// arbitrary winner. Region conflicts retain a known service and unknown region.
func ClassifyServiceRanges(sources []ServiceRangeStatus, at time.Time) ServiceClassification {
	out := ServiceClassification{Status: "unknown", Sources: sources}
	var candidates []serviceCandidate
	var supersets serviceSupersets
	for _, source := range sources {
		if source.Status != "matched" || at.Before(source.FetchedAt) || !at.Before(source.ValidUntil) {
			continue
		}
		provider := source.Publisher
		if source.Publisher == "slack_huddles" {
			continue // shared Chime media paths do not prove the Slack application
		}
		if zoom, ok := zoomRangePublishers[source.Publisher]; ok {
			if zoom.networkOnly {
				continue // retain source candidates, without asserting exclusive app use
			}
			provider = "zoom"
		}
		if _, microsoft365 := m365RangeInstances[source.Publisher]; microsoft365 {
			provider = "microsoft_365"
		}
		if cloud, azure := azureRangeClouds[source.Publisher]; azure {
			if cloud.legacy {
				continue // retired cloud originals remain provenance, not current use
			}
			provider = "azure"
		}
		for _, match := range source.Matches {
			prefix, err := netip.ParsePrefix(match.Prefix)
			if err != nil || !validServiceRangeLabel(match.Service) {
				continue
			}
			candidates = append(candidates, serviceCandidate{provider, match, prefix.Bits()})
			supersets.awsSpecific = supersets.awsSpecific || provider == "aws" && match.Service != "AMAZON"
			supersets.s3 = supersets.s3 || provider == "aws" && match.Service == "S3"
			supersets.googleCloud = supersets.googleCloud || provider == "google_cloud"
			supersets.azureSpecific = supersets.azureSpecific || provider == "azure" && match.Service != "AzureCloud"
			supersets.zoomSpecific = supersets.zoomSpecific || provider == "zoom" && match.Service != "Zoom"
			supersets.m365Specific = supersets.m365Specific || provider == "microsoft_365" && match.Service != "Microsoft 365 Common"
			supersets.saasSpecific = supersets.saasSpecific || provider == "zoom" || provider == "salesforce" || provider == "microsoft_365"
		}
	}
	best := -1
	regionConflict := false
	for _, candidate := range candidates {
		if serviceCandidateIsSuperset(candidate, supersets) {
			continue
		}
		if candidate.bits > best {
			best = candidate.bits
			out.Service, out.Provider, out.Region, out.Status = candidate.match.Service, candidate.provider, candidate.match.Region, "known"
			regionConflict = false
			continue
		}
		if candidate.bits != best {
			continue
		}
		if candidate.provider != out.Provider || candidate.match.Service != out.Service {
			out.Status = "ambiguous"
		} else if region := candidate.match.Region; region != "" && !regionConflict {
			if out.Region == "" {
				out.Region = region
			} else if region != out.Region {
				regionConflict = true
			}
		}
		if regionConflict {
			out.Region = ""
		}
	}
	if out.Status == "ambiguous" {
		out.Service, out.Provider, out.Region = "", "", ""
	}
	return out
}

func serviceCandidateIsSuperset(candidate serviceCandidate, supersets serviceSupersets) bool {
	switch candidate.provider {
	case "aws":
		return candidate.match.Service == "AMAZON" && (supersets.awsSpecific || supersets.saasSpecific) ||
			candidate.match.Service == "EC2" && (supersets.s3 || supersets.saasSpecific)
	case "google":
		return supersets.googleCloud || supersets.saasSpecific
	case "google_cloud":
		return supersets.saasSpecific
	case "azure":
		return candidate.match.Service == "AzureCloud" && (supersets.azureSpecific || supersets.saasSpecific)
	case "zoom":
		return candidate.match.Service == "Zoom" && supersets.zoomSpecific
	case "microsoft_365":
		return candidate.match.Service == "Microsoft 365 Common" && supersets.m365Specific
	default:
		return false
	}
}
