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

const azureGoldenDocument = `{
 "changeNumber":426,"cloud":"Public","values":[
 {"name":"AzureCloud","properties":{"region":"","systemService":"","addressPrefixes":["192.0.2.0/24"]}},
 {"name":"AzureCloud.eastus","properties":{"region":"eastus","systemService":"","addressPrefixes":["192.0.2.0/24"]}},
 {"name":"Storage","properties":{"region":"","systemService":"AzureStorage","addressPrefixes":["192.0.2.0/24","198.51.100.0/24","2001:db8:a::/48"]}},
 {"name":"Storage.EastUS","properties":{"region":"eastus","systemService":"AzureStorage","addressPrefixes":["192.0.2.0/24","2001:db8:a::/48"]}},
 {"name":"Storage.WestUS","properties":{"region":"westus","systemService":"AzureStorage","addressPrefixes":["198.51.100.0/24"]}}
 ]}` + "\n"

func TestAzureServiceTagsKeepEveryFamilyRegionAndOriginalVersion(t *testing.T) {
	at := time.Now().UTC()
	cache := fmt.Sprintf(`{"version":2,"sources":[{"publisher":"azure_public","fetched_at":%q,"complete":true,"data":%q}]}`, at.Format(time.RFC3339Nano), azureGoldenDocument)
	source, err := LoadServiceRanges(t.Context(), serviceRangeFile(t, cache), time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal("complete native Azure service tags refused", err)
	}
	for address, region := range map[string]string{"192.0.2.7": "eastus", "198.51.100.7": "westus", "2001:db8:a::7": "eastus"} {
		status := source.lookup(netip.MustParseAddr(address), at, true)[0]
		if status.Status != "matched" || status.Version != "426" || status.Digest != hex.EncodeToString(crypto.Hash([]byte(azureGoldenDocument))) || !status.PublishedAt.IsZero() {
			t.Fatal("Azure original identity changed or a publication clock was invented", status)
		}
		value := ClassifyServiceRanges([]ServiceRangeStatus{status}, at)
		if value.Status != "known" || value.Service != "AzureStorage" || value.Provider != "azure" || value.Region != region {
			t.Fatal("generic/global tag masked the service or its unique published region", address, value)
		}
	}
	status := source.lookup(netip.MustParseAddr("192.0.2.7"), at, true)[0]
	if len(status.Matches) != 4 {
		t.Fatal("complete overlapping source candidates were lost", status)
	}
	status.Matches = append(status.Matches,
		ServiceRangeMatch{Prefix: "192.0.2.0/24", Service: "AzureStorage", Region: "westus"},
		ServiceRangeMatch{Prefix: "192.0.2.0/24", Service: "AzureStorage", Region: "eastus"})
	value := ClassifyServiceRanges([]ServiceRangeStatus{status}, at)
	if value.Status != "known" || value.Service != "AzureStorage" || value.Region != "" {
		t.Fatal("conflicting regions became an arbitrary winner", value)
	}
	stale := source.lookup(netip.MustParseAddr("192.0.2.7"), at.Add(2*time.Hour), true)[0]
	if stale.Status != "stale" || len(stale.Matches) != 0 || !stale.FetchedAt.Equal(at) {
		t.Fatal("cached Azure source renewed original age or retained stale labels", stale)
	}
}

func TestAzureBulkDiscoversEveryCloudAndPreservesOriginalsOnUnsafeInput(t *testing.T) {
	mode := "ok"
	requests := 0
	clouds := map[string]bool{}
	client := serviceRangeDoerFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method != http.MethodGet || req.URL.Scheme != "https" || req.Header.Get("Authorization") != "" || req.Header.Get("X-Probectl-Tenant") != "" || len(req.Cookies()) != 0 {
			t.Fatal("Azure bulk request carried private context or weakened TLS")
		}
		body, age := "", "3600"
		switch req.URL.Host {
		case "www.microsoft.com":
			if req.URL.Path != "/en-us/download/details.aspx" || len(req.URL.Query()) != 1 {
				t.Fatal("Azure discovery left its fixed public page", req.URL)
			}
			var cloud azureRangeCloud
			for _, candidate := range azureRangeClouds {
				if candidate.documentID == req.URL.Query().Get("id") {
					cloud = candidate
				}
			}
			if cloud.cloud == "" {
				t.Fatal("unknown discovery document")
			}
			clouds[cloud.cloud] = true
			link := "https://download.microsoft.com/download/qa/ServiceTags_" + cloud.cloud + "_20261109.json"
			switch mode {
			case "ambiguous":
				body = `<a href="` + strings.Replace(link, "20261109", "20261102", 1) + `">other</a>`
			case "foreign":
				link = strings.Replace(link, "download.microsoft.com", "download.microsoft.com.invalid", 1)
			case "userinfo":
				link = strings.Replace(link, "https://", "https://user@", 1)
			case "escaped":
				link = strings.Replace(link, "/download/qa/", "/download/%71a/", 1)
			case "query":
				link += "?tenant=forbidden"
			case "plaintext":
				link = strings.Replace(link, "https:", "http:", 1)
			}
			body += `<html><a href="` + link + `">Download</a><a href="` + link + `">same download</a></html>`
			age = "7200"
		case "download.microsoft.com":
			if req.URL.RawQuery != "" {
				t.Fatal("cloud download carried a subset selector")
			}
			cloud := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(req.URL.Path), "ServiceTags_"), "_20261109.json")
			body = strings.Replace(azureGoldenDocument, `"cloud":"Public"`, `"cloud":"`+cloud+`"`, 1)
			if mode == "wrong-cloud" {
				body = strings.Replace(body, `"cloud":"`+cloud+`"`, `"cloud":"Other"`, 1)
			}
			if mode == "bad-prefix" {
				body = strings.Replace(body, "2001:db8:a::/48", "not-a-prefix", 1)
			}
		default:
			t.Fatal("discovery fetched an untrusted destination", req.URL)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Age": []string{age}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	cache := filepath.Join(t.TempDir(), "azure.json")
	if err := FetchServiceRangeCache(t.Context(), cache, []string{"azure"}, 24*time.Hour, 16<<20, client); err != nil {
		t.Fatal(err)
	}
	if len(clouds) != 4 || requests != 8 {
		t.Fatal("complete Azure bundle omitted or repeated a cloud", clouds, requests)
	}
	original, err := os.ReadFile(cache)
	if err != nil {
		t.Fatal(err)
	}
	var envelope serviceRangeEnvelope
	if json.Unmarshal(original, &envelope) != nil || len(envelope.Sources) != 4 {
		t.Fatal("native Azure originals missing")
	}
	for _, source := range envelope.Sources {
		expected := strings.Replace(azureGoldenDocument, `"cloud":"Public"`, `"cloud":"`+azureRangeClouds[source.Publisher].cloud+`"`, 1)
		if string(source.Data) != expected || time.Since(source.FetchedAt) < 119*time.Minute || time.Since(source.FetchedAt) > 121*time.Minute {
			t.Fatal("original bytes or oldest discovery/document age were lost", source.Publisher)
		}
	}
	loaded, err := LoadServiceRanges(t.Context(), cache, 24*time.Hour, 16<<20, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range loaded.lookup(netip.MustParseAddr("192.0.2.7"), time.Now(), true) {
		if status.Publisher == "azure_germany" && (len(status.Matches) == 0 || ClassifyServiceRanges([]ServiceRangeStatus{status}, time.Now()).Status != "unknown") {
			t.Fatal("retired Germany cloud vanished from provenance or became current attribution", status)
		}
	}
	for _, failure := range []string{"ambiguous", "foreign", "userinfo", "escaped", "query", "plaintext", "wrong-cloud", "bad-prefix"} {
		mode = failure
		before := requests
		if err := FetchServiceRangeCache(t.Context(), cache, []string{"azure_public"}, 24*time.Hour, 16<<20, client); err == nil {
			t.Fatal("unsafe/incomplete discovery reported success", failure)
		}
		if requests-before > 2 {
			t.Fatal("failed discovery silently retried", failure)
		}
		current, err := os.ReadFile(cache)
		if err != nil || !bytes.Equal(current, original) {
			t.Fatal("failed discovery changed prior source bytes or clocks", failure, err)
		}
	}
}
