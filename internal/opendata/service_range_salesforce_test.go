// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Real TLS/file replacement with QA-authored original-format source bytes.
// Salesforce publishes arrays inside each hosting-provider/region group.
func TestSalesforcePublishedRangesKeepEveryGroupedFamilyAndOriginalClock(t *testing.T) {
	body := `{"syncToken":"opaque-salesforce-version","createDate":"2026-10-16-04-32-59","prefixes":[{"region":"us-east-1","provider":"aws","ip_prefix":["192.0.2.0/25","192.0.2.128/25"]},{"region":"europe-west10","provider":"gcp","ip_prefix":["198.51.100.0/24"]}],"ipv6_prefixes":[{"region":"us-east-1","provider":"aws","ipv6_prefix":["2001:db8:1::/48","2001:db8:2::/48"]}]}`
	current := body
	var mu sync.Mutex
	publisher := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Probectl-Tenant") != "" || len(r.Cookies()) != 0 {
			t.Error("public bulk request included tenant/private selectors")
		}
		_, _ = w.Write([]byte(current))
	}))
	t.Cleanup(publisher.Close)
	target, err := url.Parse(publisher.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://ip-ranges.salesforce.com/ip-ranges.json" {
			t.Fatal("Salesforce bulk fetch escaped its canonical endpoint", req.URL)
		}
		forward := req.Clone(req.Context())
		address := *req.URL
		address.Host = target.Host
		forward.URL, forward.Host = &address, ""
		return publisher.Client().Do(forward)
	})
	path := filepath.Join(t.TempDir(), "complete.json")
	if err := FetchServiceRangeCache(t.Context(), path, []string{"salesforce"}, time.Hour, 16<<20, client); err != nil {
		t.Fatal("complete Salesforce arrays were refused", err)
	}
	original, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(original, []byte(body)) {
		t.Fatal("bulk import lost original source bytes", err)
	}
	at := time.Now().UTC()
	source, err := LoadServiceRanges(t.Context(), path, time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	for address, region := range map[string]string{"192.0.2.7": "us-east-1", "192.0.2.200": "us-east-1", "198.51.100.7": "europe-west10", "2001:db8:1::7": "us-east-1", "2001:db8:2::7": "us-east-1"} {
		status := source.lookup(netip.MustParseAddr(address), at, true)[0]
		if status.Status != "matched" || status.PublishedTime != "2026-10-16-04-32-59" || status.Version != "opaque-salesforce-version" || !status.PublishedAt.IsZero() || len(status.Matches) != 1 {
			t.Fatal("lost complete Salesforce provenance or invented a clock", status)
		}
		value := ClassifyServiceRanges([]ServiceRangeStatus{status}, at)
		if value.Status != "known" || value.Service != "Salesforce" || value.Provider != "salesforce" || value.Region != region {
			t.Fatal("source was confused with the hosting provider or another product", value)
		}
		stale := source.lookup(netip.MustParseAddr(address), at.Add(2*time.Hour), true)[0]
		if stale.Status != "stale" || len(stale.Matches) != 0 || !stale.FetchedAt.Equal(status.FetchedAt) {
			t.Fatal("stale source retained labels or renewed its original age", stale)
		}
	}
	for _, invalid := range []string{
		strings.Replace(body, `"192.0.2.0/25"`, `"2001:db8::/32"`, 1),
		strings.Replace(body, `"2001:db8:1::/48"`, `"192.0.2.0/24"`, 1),
		strings.Replace(body, `"ip_prefix":["192.0.2.0/25","192.0.2.128/25"]`, `"ip_prefix":null`, 1),
		strings.Replace(body, `"provider":"aws"`, `"provider":""`, 1),
		strings.Replace(body, `"createDate":"2026-10-16-04-32-59"`, `"createDate":"invalid"`, 1),
		strings.Replace(body, `"syncToken":"opaque-salesforce-version"`, `"syncToken":"one","syncToken":"two"`, 1),
	} {
		mu.Lock()
		current = invalid
		mu.Unlock()
		if err := FetchServiceRangeCache(t.Context(), path, []string{"salesforce"}, time.Hour, 16<<20, client); err == nil {
			t.Fatal("malformed source partially replaced complete cache")
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, original) {
			t.Fatal("failed source replaced original bytes or clocks", err)
		}
	}
	var envelope serviceRangeEnvelope
	if err := json.Unmarshal(original, &envelope); err != nil || len(envelope.Sources) != 1 {
		t.Fatal("complete offline envelope changed", err)
	}
}
