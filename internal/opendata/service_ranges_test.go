// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// QA-authored addresses/labels in the documented vendor schemas. These are
// not downloaded datasets or proof of publisher coverage.
const serviceRangeFixture = `{"version":1,"sources":[
{"publisher":"aws","fetched_at":"2026-11-15T09:00:00Z","complete":true,"data":{
"syncToken":"1763200000","createDate":"2026-11-14-09-00-00","prefixes":[
{"ip_prefix":"192.0.2.0/24","region":"GLOBAL","service":"AMAZON","network_border_group":"GLOBAL"},
{"ip_prefix":"192.0.2.0/25","region":"us-east-1","service":"S3"},
{"ip_prefix":"192.0.2.0/25","region":"us-east-1","service":"EC2"}],
"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32","region":"us-west-2","service":"CLOUDFRONT"}]}},
{"publisher":"google_cloud","fetched_at":"2026-11-15T09:00:00Z","complete":true,"data":{
"syncToken":"1763200000000000","creationTime":"2026-11-14T09:00:00.123456Z","prefixes":[
{"ipv4Prefix":"198.51.100.0/24","service":"Google Cloud","scope":"europe-west1"},
{"ipv6Prefix":"2001:db8:abcd::/48","service":"Google Cloud","scope":"us-central1"}]}},
{"publisher":"google","fetched_at":"2026-11-15T09:00:00Z","complete":true,"data":{
"syncToken":"1763200000000000","creationTime":"2026-11-14T09:00:00Z","prefixes":[{"ipv4Prefix":"203.0.113.0/24"}]}}
]}`

func serviceRangeFile(t testing.TB, raw string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service-ranges.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPublishedServiceRangesKeepCompleteOverlapClocksAndOfflineCacheFreshness(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	source, err := LoadServiceRanges(ctx, serviceRangeFile(t, serviceRangeFixture), 24*time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct {
		address, publisher, service, region string
		matches                             int
	}{
		{"192.0.2.7", "aws", "S3", "us-east-1", 3},
		{"192.0.2.200", "aws", "AMAZON", "GLOBAL", 1},
		{"2001:db8::1", "aws", "CLOUDFRONT", "us-west-2", 1},
		{"198.51.100.7", "google_cloud", "Google Cloud", "europe-west1", 1},
		{"2001:db8:abcd::1", "google_cloud", "Google Cloud", "us-central1", 1},
		{"203.0.113.7", "google", "Google", "global", 1},
	} {
		t.Run(example.address, func(t *testing.T) {
			statuses := source.lookup(netip.MustParseAddr(example.address), at, true)
			publisherFound := false
			for _, status := range statuses {
				if status.Publisher != example.publisher {
					continue
				}
				publisherFound = true
				if status.Status != "matched" || len(status.Matches) != example.matches || len(status.Digest) != 64 || status.FetchedAt.Hour() != 9 || status.PublishedAt.IsZero() || status.TermsURL == "" {
					t.Fatal("lost complete original source", status)
				}
				found := false
				for _, match := range status.Matches {
					found = found || (match.Service == example.service && match.Region == example.region)
				}
				if !found {
					t.Fatal("publisher label was lost", status)
				}
			}
			if !publisherFound {
				t.Fatal("publisher disappeared from the complete source")
			}
		})
	}
	for _, status := range source.lookup(netip.MustParseAddr("192.0.2.7"), at.Add(24*time.Hour), true) {
		if status.Status != "stale" || len(status.Matches) != 0 || status.FetchedAt.IsZero() {
			t.Fatal("stale source still attributed traffic or lost its age", status)
		}
	}
	for _, status := range source.lookup(netip.MustParseAddr("192.0.2.7"), at, false) {
		if status.Status != "disabled" || len(status.Matches) != 0 {
			t.Fatal("disabled source still attributed traffic", status)
		}
	}
	// Mutating an owned result cannot change the immutable shared index.
	first := source.lookup(netip.MustParseAddr("192.0.2.7"), at, true)
	first[0].Matches[0].Service = "foreign tenant mutation"
	if source.lookup(netip.MustParseAddr("192.0.2.7"), at, true)[0].Matches[0].Service == "foreign tenant mutation" {
		t.Fatal("lookup returned mutable shared source memory")
	}
	// A cached IP is materialized with today's source validity, not the cached
	// object's prior matched labels. Neither restart nor cache TTL renews it.
	en := NewEnricher(discardLogger())
	en.Register(source)
	en.cache.put("192.0.2.7", Enrichment{IP: "192.0.2.7", ASN: 64500, Services: first})
	source.datasets[0].status.ValidUntil = time.Now().Add(-time.Hour)
	value, err := en.Enrich(ctx, "192.0.2.7")
	if err != nil || value.ASN != 64500 || value.Services[0].Status != "stale" || len(value.Services[0].Matches) != 0 {
		t.Fatal("IP cache resurrected a stale service source", value, err)
	}
	if status := en.Status(); len(status) != 1 || status[0].Health.Status != "unavailable" {
		t.Fatal("stale list vanished from health", status)
	}
}

func TestPublishedServiceRangesRefuseIncompleteUntrustedOrOverBudgetInput(t *testing.T) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	for name, raw := range map[string]string{
		"partial":                          strings.Replace(serviceRangeFixture, `"complete":true`, `"complete":false`, 1),
		"duplicate completeness":           strings.Replace(serviceRangeFixture, `"complete":true`, `"complete":false,"complete":true`, 1),
		"case-fold duplicate completeness": strings.Replace(serviceRangeFixture, `"complete":true`, `"Complete":false,"complete":true`, 1),
		"wrong envelope field case":        strings.Replace(serviceRangeFixture, `"complete":true`, `"Complete":true`, 1),
		"duplicate vendor key":             strings.Replace(serviceRangeFixture, `"region":"GLOBAL"`, `"region":"foreign","region":"GLOBAL"`, 1),
		"trailing":                         serviceRangeFixture + `{}`,
		"future fetch":                     strings.Replace(serviceRangeFixture, `2026-11-15T09:00:00Z`, `2026-11-16T09:00:00Z`, 1),
		"future publication":               strings.Replace(serviceRangeFixture, `2026-11-14-09-00-00`, `2026-11-16-09-00-00`, 1),
		"missing family":                   strings.Replace(serviceRangeFixture, `"ipv6_prefixes":[`, `"other":[`, 1),
		"null family":                      strings.Replace(serviceRangeFixture, `"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32","region":"us-west-2","service":"CLOUDFRONT"}]`, `"ipv6_prefixes":null`, 1),
		"malformed prefix":                 strings.Replace(serviceRangeFixture, `192.0.2.0/24`, `not-a-prefix`, 1),
		"wrong publisher":                  strings.Replace(serviceRangeFixture, `"publisher":"aws"`, `"publisher":"unapproved"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if source, err := LoadServiceRanges(context.Background(), serviceRangeFile(t, raw), time.Hour, 16<<20, at); err == nil || source != nil {
				t.Fatal("incomplete source was partially admitted", source, err)
			}
		})
	}
	path := serviceRangeFile(t, serviceRangeFixture)
	if source, err := LoadServiceRanges(context.Background(), path, time.Hour, 4096, at); !errors.Is(err, ErrServiceRangeBudget) || source != nil {
		t.Fatal("budget returned a partial index", source, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if source, err := LoadServiceRanges(ctx, path, time.Hour, 16<<20, at); !errors.Is(err, context.Canceled) || source != nil {
		t.Fatal("canceled import admitted data", source, err)
	}
	// Verify the synthetic fixture remains a complete JSON document.
	if !json.Valid([]byte(serviceRangeFixture)) {
		t.Fatal("invalid test fixture")
	}
}
