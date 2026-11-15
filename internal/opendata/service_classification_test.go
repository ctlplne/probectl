// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestPublishedServiceClassificationKeepsSpecificityConflictsAndCurrentSourceExpiry(t *testing.T) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	status := func(provider string, matches ...ServiceRangeMatch) ServiceRangeStatus {
		return ServiceRangeStatus{Publisher: provider, Status: "matched", FetchedAt: at.Add(-time.Minute), ValidUntil: at.Add(time.Hour), Matches: matches}
	}
	for _, example := range []struct {
		name                             string
		input                            []ServiceRangeStatus
		service, provider, region, state string
	}{
		{"AWS documented subsets", []ServiceRangeStatus{status("aws", ServiceRangeMatch{"192.0.2.0/24", "AMAZON", "GLOBAL"}, ServiceRangeMatch{"192.0.2.0/25", "EC2", "us-east-1"}, ServiceRangeMatch{"192.0.2.0/25", "S3", "us-east-1"})}, "S3", "aws", "us-east-1", "known"},
		{"generic narrower prefix cannot hide S3", []ServiceRangeStatus{status("aws", ServiceRangeMatch{"192.0.2.0/26", "AMAZON", "GLOBAL"}, ServiceRangeMatch{"192.0.2.0/24", "S3", "us-east-1"})}, "S3", "aws", "us-east-1", "known"},
		{"Google cloud subset", []ServiceRangeStatus{status("google", ServiceRangeMatch{"192.0.2.0/26", "Google", "global"}), status("google_cloud", ServiceRangeMatch{"192.0.2.0/24", "Google Cloud", "us-west1"})}, "Google Cloud", "google_cloud", "us-west1", "known"},
		{"unknown tied service", []ServiceRangeStatus{status("aws", ServiceRangeMatch{"192.0.2.0/24", "S3", "us-east-1"}), status("cloudflare", ServiceRangeMatch{"192.0.2.0/24", "Cloudflare", ""})}, "", "", "", "ambiguous"},
		{"more specific service", []ServiceRangeStatus{status("aws", ServiceRangeMatch{"192.0.2.0/24", "AMAZON", "GLOBAL"}), status("cloudflare", ServiceRangeMatch{"192.0.2.0/25", "Cloudflare", ""})}, "Cloudflare", "cloudflare", "", "known"},
		{"unknown tied region", []ServiceRangeStatus{status("aws", ServiceRangeMatch{"192.0.2.0/24", "S3", "us-east-1"}, ServiceRangeMatch{"192.0.2.0/24", "S3", "us-west-2"})}, "S3", "aws", "", "known"},
	} {
		t.Run(example.name, func(t *testing.T) {
			value := ClassifyServiceRanges(example.input, at)
			if value.Service != example.service || value.Provider != example.provider || value.Region != example.region || value.Status != example.state || len(value.Sources) != len(example.input) {
				t.Fatal("published candidates changed or ambiguous winner invented", value)
			}
			for i := range example.input {
				if len(value.Sources[i].Matches) != len(example.input[i].Matches) {
					t.Fatal("source candidates truncated")
				}
			}
		})
	}
	source, err := LoadServiceRanges(context.Background(), serviceRangeFile(t, serviceRangeFixture), 24*time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	en := NewEnricher(discardLogger())
	en.Register(source)
	// An unrelated cached enrichment cannot control authoritative local matching.
	en.cache.put("192.0.2.7", Enrichment{IP: "192.0.2.7", ASN: 64500})
	current := en.LocalServiceRanges(t.Context(), "192.0.2.7", at)
	if value := ClassifyServiceRanges(current, at); value.Service != "S3" || value.Status != "known" {
		t.Fatal("cache warm state hid local source", value)
	}
	if value := ClassifyServiceRanges(current, at.Add(25*time.Hour)); value.Status != "unknown" || value.Service != "" {
		t.Fatal("cached candidates resurrected expired source", value)
	}
	if got := en.LocalServiceRanges(t.Context(), "192.0.2.7", at.Add(25*time.Hour)); ClassifyServiceRanges(got, at.Add(25*time.Hour)).Status != "unknown" {
		t.Fatal("expired source became authoritative")
	}
	en.setEnabled(source.Descriptor().Name, false)
	if value := ClassifyServiceRanges(en.LocalServiceRanges(t.Context(), "192.0.2.7", at), at); value.Status != "unknown" {
		t.Fatal("disabled local source still classified traffic", value)
	}
	if source.lookup(netip.MustParseAddr("192.0.2.7"), at, true)[0].Matches[0].Service == "" {
		t.Fatal("classification mutated original index")
	}
}
