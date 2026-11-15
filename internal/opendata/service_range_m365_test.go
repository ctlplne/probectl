// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const m365GoldenDocument = `[
 {"id":1,"serviceArea":"Common","ips":["192.0.2.0/24","198.51.100.0/24"],"category":"Allow","required":true},
 {"id":2,"serviceArea":"Exchange","serviceAreaDisplayName":"Exchange Online","ips":["192.0.2.0/25","2001:db8:1::/48"],"category":"Optimize","required":true},
 {"id":3,"serviceArea":"SharePoint","ips":["203.0.113.0/24"],"category":"Allow","required":false},
 {"id":4,"serviceArea":"Skype","ips":["2001:db8:2::7"],"category":"Optimize","required":true},
 {"id":5,"serviceArea":"Exchange","urls":["*.outlook.example"],"category":"Default","required":true}
]` + "\n"

func TestM365PublishedOfflineKeepsEveryAreaFamilyAndOriginalIdentity(t *testing.T) {
	at := time.Now().UTC()
	cache := fmt.Sprintf(`{"version":2,"sources":[{"publisher":"m365_worldwide","fetched_at":%q,"complete":true,"data":%q}]}`, at.Format(time.RFC3339Nano), m365GoldenDocument)
	source, err := LoadServiceRanges(t.Context(), serviceRangeFile(t, cache), time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal("complete offline Microsoft365 service areas/families refused", err)
	}
	for address, service := range map[string]string{"192.0.2.7": "Microsoft 365 Exchange", "198.51.100.7": "Microsoft 365 Common", "203.0.113.7": "Microsoft 365 SharePoint", "2001:db8:1::7": "Microsoft 365 Exchange", "2001:db8:2::7": "Microsoft 365 Skype"} {
		status := source.lookup(netip.MustParseAddr(address), at, true)[0]
		if status.Status != "matched" || status.Digest != hex.EncodeToString(crypto.Hash([]byte(m365GoldenDocument))) || !status.PublishedAt.IsZero() || status.Version != "sha256:"+status.Digest {
			t.Fatal("original source identity was lost or a publication clock guessed", status)
		}
		value := ClassifyServiceRanges([]ServiceRangeStatus{status}, at)
		if value.Status != "known" || value.Service != service || value.Provider != "microsoft_365" || value.Region != "" {
			t.Fatal("area/family attribution changed or instance became an invented region", address, value)
		}
		encoded, err := json.Marshal(value)
		if err != nil || bytes.Contains(encoded, []byte(`"published_at"`)) {
			t.Fatal("unknown publisher clock became a date", err)
		}
	}
	status := source.lookup(netip.MustParseAddr("2001:db8:2::8"), at, true)[0]
	if len(status.Matches) != 0 {
		t.Fatal("bare IPv6 endpoint widened beyond its exact host")
	}
	stale := source.lookup(netip.MustParseAddr("192.0.2.7"), at.Add(2*time.Hour), true)[0]
	if stale.Status != "stale" || len(stale.Matches) != 0 || !stale.FetchedAt.Equal(at) {
		t.Fatal("old endpoint source retained labels or renewed original age", stale)
	}
}

func TestM365PublishedBulkKeepsAllInstancesAndOnlyExplicitMachineAssociation(t *testing.T) {
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	mode := "ok"
	instances := map[string]bool{}
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		query := req.URL.Query()
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.URL.Host != "endpoints.office.com" || len(query) != 1 || query.Get("ClientRequestId") != id || req.Header.Get("Authorization") != "" || req.Header.Get("X-Probectl-Tenant") != "" || len(req.Cookies()) != 0 {
			t.Fatal("Microsoft365 request included private selectors or narrowed the complete export")
		}
		instance := strings.TrimPrefix(req.URL.Path, "/endpoints/")
		instances[instance] = true
		body, status := m365GoldenDocument, http.StatusOK
		if mode == "throttled" {
			status = http.StatusTooManyRequests
		}
		if mode == "malformed" {
			body = strings.Replace(body, `"192.0.2.0/25"`, `"not an address"`, 1)
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Age": []string{"3600"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	path := filepath.Join(t.TempDir(), "ranges.json")
	for _, invalid := range []string{"", "not-a-guid"} {
		if err := FetchServiceRangeCacheWithOptions(t.Context(), path, []string{"aws", "m365"}, 24*time.Hour, 16<<20, ServiceRangeFetchOptions{Microsoft365ClientRequestID: invalid}, client); err == nil || requests != 0 {
			t.Fatal("incomplete association performed any source request")
		}
	}
	options := ServiceRangeFetchOptions{Microsoft365ClientRequestID: id}
	if err := FetchServiceRangeCacheWithOptions(t.Context(), path, []string{"m365"}, 24*time.Hour, 16<<20, options, client); err != nil {
		t.Fatal(err)
	}
	for _, instance := range []string{"Worldwide", "China", "USGovDoD", "USGovGCCHigh"} {
		if !instances[instance] {
			t.Fatal("complete bundle omitted a published instance", instance)
		}
	}
	if requests != 4 {
		t.Fatal("bulk fetch repeated source requests", requests)
	}
	original, err := os.ReadFile(path)
	if err != nil || bytes.Contains(original, []byte(id)) {
		t.Fatal("machine association leaked into the shared source cache", err)
	}
	var envelope serviceRangeEnvelope
	if json.Unmarshal(original, &envelope) != nil || len(envelope.Sources) != 4 {
		t.Fatal("bulk source omitted complete original documents")
	}
	for _, input := range envelope.Sources {
		if !bytes.Equal(input.Data, []byte(m365GoldenDocument)) || time.Since(input.FetchedAt) < 59*time.Minute {
			t.Fatal("original bytes lost or HTTP Age renewed", input.Publisher)
		}
	}
	for _, failure := range []string{"throttled", "malformed"} {
		mode = failure
		before := requests
		if err := FetchServiceRangeCacheWithOptions(t.Context(), path, []string{"m365_worldwide"}, 24*time.Hour, 16<<20, options, client); err == nil || requests != before+1 {
			t.Fatal("failed source retried, rotated association or reported success", failure)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, original) {
			t.Fatal("failed source replaced prior bytes or original age", failure, err)
		}
	}
}
