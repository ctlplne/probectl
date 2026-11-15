// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type publishedRangeFetchDoer func(*http.Request) (*http.Response, error)

func (f publishedRangeFetchDoer) Do(req *http.Request) (*http.Response, error) { return f(req) }

// Real app-role PostgreSQL/FORCE-RLS, sessions and HTTPS SDK. The original
// publisher-format input is QA-authored, not downloaded publisher evidence.
func TestPublishedServiceRangeAPIKeepsTwoCurrentTenantReadersAndOfflineStartup(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	fetched := time.Now().UTC().Add(-time.Minute)
	document := map[string]any{"version": 1, "sources": []any{map[string]any{
		"publisher": "aws", "complete": true, "fetched_at": fetched,
		"data": map[string]any{"syncToken": "qa-original", "createDate": fetched.Add(-time.Hour).Format("2006-01-02-15-04-05"),
			"prefixes": []any{map[string]string{"ip_prefix": "192.0.2.0/24", "service": "S3", "region": "us-east-1"}}, "ipv6_prefixes": []any{}},
	}}}
	raw, err := json.Marshal(document["sources"].([]any)[0].(map[string]any)["data"])
	if err != nil {
		t.Fatal(err)
	}
	salesforce := []byte(`{"syncToken":"qa-sf-original","createDate":"2026-10-16-04-32-59","prefixes":[{"provider":"aws","region":"us-east-1","ip_prefix":["192.0.2.0/24"]}],"ipv6_prefixes":[]}`)
	cloudflare := []byte(`{"success":true,"result":{"etag":"qa-cf-original","ipv4_cidrs":["192.0.2.0/24"],"ipv6_cidrs":[]}}`)
	requestID, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "complete.json")
	publisher := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "www.microsoft.com" {
			_, _ = w.Write([]byte(`<a href="https://download.microsoft.com/download/qa/ServiceTags_Public_20261109.json">Download</a>`))
			return
		}
		if r.Host == "download.microsoft.com" {
			_, _ = w.Write([]byte(`{"changeNumber":426,"cloud":"Public","values":[{"name":"Storage.EastUS","properties":{"region":"eastus","systemService":"AzureStorage","addressPrefixes":["192.0.2.0/24","2001:db8:a::/48"]}}]}`))
			return
		}
		if r.Host == "endpoints.office.com" {
			query := r.URL.Query()
			if r.Method != http.MethodGet || len(query) != 1 || query.Get("ClientRequestId") != requestID || r.Header.Get("Authorization") != "" || r.Header.Get("X-Probectl-Tenant") != "" {
				t.Error("Microsoft365 bulk request carried private or subset selectors")
			}
			_, _ = w.Write([]byte(`[{"id":1,"serviceArea":"Exchange","ips":["192.0.2.0/24","2001:db8::/32"]},{"id":2,"serviceArea":"Common","urls":["*.office.example"]}]`))
			return
		}
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Probectl-Tenant") != "" {
			t.Error("bulk public request carried a tenant selector")
		}
		if r.Host == "assets.zoom.us" && r.URL.Path == "/docs/ipranges/ZoomMeetings.txt" {
			_, _ = w.Write([]byte("\r\n192.0.2.0/24\r\n"))
			return
		}
		if r.Host == "ip-ranges.salesforce.com" {
			_, _ = w.Write(salesforce)
			return
		}
		if r.URL.Path == "/client/v4/ips" {
			_, _ = w.Write(cloudflare)
			return
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(publisher.Close)
	target, err := url.Parse(publisher.URL)
	if err != nil {
		t.Fatal(err)
	}
	download := publishedRangeFetchDoer(func(req *http.Request) (*http.Response, error) {
		forward := req.Clone(req.Context())
		address := *req.URL
		address.Scheme, address.Host = target.Scheme, target.Host
		forward.URL = &address
		forward.Host = req.URL.Host
		return publisher.Client().Do(forward)
	})
	if err := opendata.FetchServiceRangeCacheWithOptions(t.Context(), path, []string{"aws", "cloudflare", "salesforce", "zoom_meetings_ipv4", "m365_worldwide", "azure_public"}, time.Hour, 16<<20, opendata.ServiceRangeFetchOptions{Microsoft365ClientRequestID: requestID}, download); err != nil {
		t.Fatal(err)
	}
	cached, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Sources []struct {
			FetchedAt time.Time `json:"fetched_at"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(cached, &envelope); err != nil || len(envelope.Sources) != 6 {
		t.Fatal("complete bulk cache missing", err)
	}
	fetched = envelope.Sources[0].FetchedAt
	cfg := &config.Config{FlowEnrichServiceFile: path, FlowEnrichServiceMaxAge: time.Hour, FlowEnrichServiceMemoryBytes: 16 << 20, FlowEnrichCacheMax: 16}
	en, enabled := BuildEnrichment(cfg, statusQuietLog())
	if !enabled || en == nil || len(en.Status()) != 1 {
		t.Fatal("offline source was not wired")
	}
	// The file disappears after ONE startup import; both tenants can only use
	// the shared immutable copy. There is no publisher network fallback.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	f.server.WithOpenDataStatus(en, nil, nil)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	caFile := filepath.Join(t.TempDir(), "api-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	clients := map[string]*sdk.Client{}
	address := "192.0.2.7"
	var first map[string]any
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, scope tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, scope, f.roles[tenant], "flow.read")
		})
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		clients[tenant] = client
		value, err := client.GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address})
		if err != nil {
			t.Fatal("current tenant cannot read public source", err)
		}
		services, ok := value["services"].([]any)
		if !ok || len(services) != 6 {
			t.Fatal("complete source missing", value)
		}
		byPublisher := map[string]map[string]any{}
		for _, service := range services {
			source := service.(map[string]any)
			byPublisher[source["publisher"].(string)] = source
		}
		status := byPublisher["aws"]
		matches := status["matches"].([]any)
		if status["publisher"] != "aws" || status["status"] != "matched" || len(matches) != 1 || matches[0].(map[string]any)["service"] != "S3" || status["fetched_at"] != fetched.Format(time.RFC3339Nano) {
			t.Fatal("lost original labels or clock", status)
		}
		cloud := byPublisher["cloudflare"]
		cloudMatches := cloud["matches"].([]any)
		_, inventedPublication := cloud["published_at"]
		if cloud["publisher"] != "cloudflare" || cloud["status"] != "matched" || inventedPublication || len(cloudMatches) != 1 || cloudMatches[0].(map[string]any)["region"] != "" {
			t.Fatal("Cloudflare source lost complete attribution or fabricated a clock/region", cloud)
		}
		sf := byPublisher["salesforce"]
		sfMatches := sf["matches"].([]any)
		_, inventedSFClock := sf["published_at"]
		if sf["publisher"] != "salesforce" || sf["status"] != "matched" || inventedSFClock || len(sfMatches) != 1 || sfMatches[0].(map[string]any)["service"] != "Salesforce" || sfMatches[0].(map[string]any)["region"] != "us-east-1" {
			t.Fatal("Salesforce source lost its scope, complete arrays or original clock", sf)
		}
		zoom := byPublisher["zoom_meetings_ipv4"]
		zoomMatches := zoom["matches"].([]any)
		_, inventedZoomClock := zoom["published_at"]
		if zoom["publisher"] != "zoom_meetings_ipv4" || zoom["status"] != "matched" || inventedZoomClock || len(zoomMatches) != 1 || zoomMatches[0].(map[string]any)["service"] != "Zoom Meetings" || zoomMatches[0].(map[string]any)["region"] != "" {
			t.Fatal("Zoom text source lost its product/family scope or fabricated a region/clock", zoom)
		}
		microsoft365 := byPublisher["m365_worldwide"]
		m365Matches := microsoft365["matches"].([]any)
		_, inventedM365Clock := microsoft365["published_at"]
		if microsoft365["publisher"] != "m365_worldwide" || microsoft365["status"] != "matched" || inventedM365Clock || len(m365Matches) != 1 || m365Matches[0].(map[string]any)["service"] != "Microsoft 365 Exchange" || m365Matches[0].(map[string]any)["region"] != "" {
			t.Fatal("Microsoft365 source lost its area/family scope or fabricated a clock/region", microsoft365)
		}
		azure := byPublisher["azure_public"]
		azureMatches := azure["matches"].([]any)
		_, inventedAzureClock := azure["published_at"]
		if azure["publisher"] != "azure_public" || azure["status"] != "matched" || azure["version"] != "426" || inventedAzureClock || len(azureMatches) != 1 || azureMatches[0].(map[string]any)["service"] != "AzureStorage" || azureMatches[0].(map[string]any)["region"] != "eastus" {
			t.Fatal("Azure native source lost its version/service/region or invented a publication clock", azure)
		}
		if first != nil && !reflect.DeepEqual(first, value) {
			t.Fatal("public cache changed between tenant readers", first, value)
		}
		first = value
		var output, stderr bytes.Buffer
		code := cli.RunWithStdin([]string{"--json", "--url", socket.URL, "--token", f.tokens[tenant], "--ca-file", caFile, "opendata", "enrich", "--query", "ip=" + address}, func(string) string { return "" }, bytes.NewReader(nil), &output, &stderr)
		var viaCLI map[string]any
		if code != 0 || json.Unmarshal(output.Bytes(), &viaCLI) != nil || !reflect.DeepEqual(value, viaCLI) {
			t.Fatal("CLI lost complete current public range attribution", code, stderr.String())
		}
	}
	primary, sibling := f.tenants[0], f.tenants[1]
	foreign := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[primary]), sdk.WithTenant(sibling))
	if _, err := foreign.GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address}); err == nil {
		t.Fatal("shared public data bypassed authenticated tenant boundary")
	}
	f.in(primary, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='flow.read'`, primary, f.roles[primary])
		return err
	})
	if _, err := clients[primary].GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address}); err == nil {
		t.Fatal("cached source bypassed current user permission withdrawal")
	}
	if _, err := clients[sibling].GetOpenDataEnrichment(t.Context(), sdk.GetOpenDataEnrichmentRequest{Ip: &address}); err != nil {
		t.Fatal("sibling lost its current source access", err)
	}
	missing, ok := BuildEnrichment(cfg, statusQuietLog())
	if !ok || missing == nil || missing.Status()[0].Health.Status != "unavailable" {
		t.Fatal("missing offline file disappeared or enabled network fallback")
	}
	value, err := missing.Enrich(t.Context(), address)
	if err != nil || len(value.Services) != 1 || value.Services[0].Status != "unavailable" || len(value.Services[0].Matches) != 0 {
		t.Fatal("missing source did not degrade to visible unknown", value, err)
	}
}
