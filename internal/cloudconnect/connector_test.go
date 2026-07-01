// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cloudconnect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/flow"
)

func TestCloudConnectorPullsAWSAzureGCPFixturesTenantScoped(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	cases := []struct {
		provider Provider
		region   string
		rawName  string
		format   string
		uri      string
	}{
		{ProviderAWS, "us-east-1", "NetworkOut", flow.ProtoAWSVPCFlowLogs, "s3://flow-bucket/AWSLogs/123/vpc.log.gz"},
		{ProviderAzure, "eastus", "BytesOut", flow.ProtoAzureNSGFlowLogs, "azure://storageacct/insights-logs-networksecuritygroupflowevent/blob.json"},
		{ProviderGCP, "us-central1", "sent_bytes_count", flow.ProtoGCPVPCFlowLogs, "gs://flow-bucket/compute.googleapis.com/vpc_flows.json"},
	}

	for _, tc := range cases {
		t.Run(string(tc.provider), func(t *testing.T) {
			var sawRequest bool
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sawRequest = true
				if r.Method != http.MethodGet {
					t.Fatalf("method = %s, want GET", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer fixture-token" {
					t.Fatalf("auth header = %q", got)
				}
				if r.URL.Query().Get("account_id") != "acct-1" || r.URL.Query().Get("region") != tc.region {
					t.Fatalf("query = %s", r.URL.RawQuery)
				}
				_ = json.NewEncoder(w).Encode(snapshotPayload{
					TenantID: "attacker-tenant",
					Metrics: []metricPayload{{
						TenantID:   "attacker-tenant",
						Region:     tc.region,
						ResourceID: "resource-1",
						Name:       tc.rawName,
						Unit:       "By",
						Value:      42,
						Timestamp:  now,
						Labels:     map[string]string{"az": tc.region + "-a"},
					}},
					FlowObjects: []flowObjectPayload{{
						TenantID:  "attacker-tenant",
						Region:    tc.region,
						URI:       tc.uri,
						UpdatedAt: now,
						SizeBytes: 2048,
					}},
				})
			}))
			defer srv.Close()
			client := srv.Client()
			client.Timeout = time.Second

			conn, err := NewConnector(Config{
				TenantID:  "tenant-a",
				Provider:  tc.provider,
				AccountID: "acct-1",
				Region:    tc.region,
				Endpoint:  srv.URL,
				Credential: Credential{
					Principal: "cloud-reader",
					Token:     "fixture-token",
					Scopes:    RequiredReadScopes(tc.provider),
				},
				Client: client,
				Now:    func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}

			snap, err := conn.Pull(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !sawRequest {
				t.Fatal("fixture endpoint was not called")
			}
			if snap.TenantID != "tenant-a" || snap.Provider != tc.provider || snap.AccountID != "acct-1" {
				t.Fatalf("snapshot scope = %+v", snap)
			}
			if snap.Cached || snap.Degraded || snap.Error != "" {
				t.Fatalf("fresh pull should not be cached/degraded: %+v", snap)
			}
			if len(snap.Metrics) != 1 {
				t.Fatalf("metrics = %d, want 1", len(snap.Metrics))
			}
			metric := snap.Metrics[0]
			if metric.TenantID != "tenant-a" || metric.Provider != tc.provider || metric.AccountID != "acct-1" {
				t.Fatalf("metric tenant scope leaked payload tenant: %+v", metric)
			}
			if !strings.HasPrefix(metric.Name, "cloud."+string(tc.provider)+".") || metric.Value != 42 {
				t.Fatalf("metric normalization failed: %+v", metric)
			}
			if strings.Contains(metric.Provenance["cloud.endpoint_host"], "fixture-token") {
				t.Fatalf("provenance leaked token: %+v", metric.Provenance)
			}
			if len(snap.FlowObjects) != 1 {
				t.Fatalf("flow objects = %d, want 1", len(snap.FlowObjects))
			}
			obj := snap.FlowObjects[0]
			if obj.TenantID != "tenant-a" || obj.Format != tc.format || obj.URI != tc.uri {
				t.Fatalf("flow object normalization failed: %+v", obj)
			}
		})
	}
}

func TestCloudConnectorCredentialScopeAndEndpointFailClosed(t *testing.T) {
	base := Config{
		TenantID:  "tenant-a",
		Provider:  ProviderAWS,
		AccountID: "acct-1",
		Region:    "us-east-1",
		Endpoint:  "https://cloud-fixture.example/snapshot",
		Credential: Credential{
			Principal: "cloud-reader",
			Token:     "tok",
			Scopes:    RequiredReadScopes(ProviderAWS),
		},
	}
	if _, err := NewConnector(base); err != nil {
		t.Fatalf("valid read-only config rejected: %v", err)
	}

	plain := base
	plain.Endpoint = "http://cloud-fixture.example/snapshot"
	if _, err := NewConnector(plain); !errors.Is(err, ErrHTTPSEndpoint) {
		t.Fatalf("plain HTTP err = %v, want HTTPS endpoint failure", err)
	}

	missing := base
	missing.Credential.Scopes = []string{"cloudwatch:GetMetricData"}
	if _, err := NewConnector(missing); !errors.Is(err, ErrReadOnlyCredentials) {
		t.Fatalf("missing read scope err = %v, want read-only credential failure", err)
	}

	writeCapable := base
	writeCapable.Credential.Scopes = append(RequiredReadScopes(ProviderAWS), "ec2:CreateFlowLogs")
	if _, err := NewConnector(writeCapable); !errors.Is(err, ErrReadOnlyCredentials) {
		t.Fatalf("write scope err = %v, want read-only credential failure", err)
	}

	unknown := base
	unknown.Provider = Provider("oracle")
	if _, err := NewConnector(unknown); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("unknown provider err = %v, want unknown provider", err)
	}
}

func TestCloudConnectorDownSourceDegradesToCachedSnapshot(t *testing.T) {
	now := time.Date(2026, 6, 30, 13, 0, 0, 0, time.UTC)
	down := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if down {
			http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(snapshotPayload{
			Metrics: []metricPayload{{
				ResourceID: "eni-1",
				Name:       "NetworkOut",
				Unit:       "By",
				Value:      100,
				Timestamp:  now,
			}},
			FlowObjects: []flowObjectPayload{{
				URI:       "s3://flow-bucket/vpc.log",
				UpdatedAt: now,
				SizeBytes: 1000,
			}},
		})
	}))
	defer srv.Close()
	client := srv.Client()
	client.Timeout = time.Second

	conn, err := NewConnector(Config{
		TenantID:  "tenant-a",
		Provider:  ProviderAWS,
		AccountID: "acct-1",
		Region:    "us-east-1",
		Endpoint:  srv.URL,
		Credential: Credential{
			Principal: "cloud-reader",
			Token:     "fixture-token",
			Scopes:    RequiredReadScopes(ProviderAWS),
		},
		Client: client,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := conn.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Metrics) != 1 || fresh.Degraded || fresh.Cached {
		t.Fatalf("fresh snapshot = %+v", fresh)
	}

	down = true
	cached, err := conn.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !cached.Degraded || !cached.Cached || !strings.Contains(cached.Error, "status 503") {
		t.Fatalf("degraded cached snapshot = %+v", cached)
	}
	if len(cached.Metrics) != 1 || cached.Metrics[0].TenantID != "tenant-a" {
		t.Fatalf("cached metrics lost tenant scope: %+v", cached.Metrics)
	}
	if strings.Contains(cached.Error, "fixture-token") {
		t.Fatalf("degraded error leaked token: %s", cached.Error)
	}

	noCacheSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
	}))
	defer noCacheSrv.Close()
	noCacheClient := noCacheSrv.Client()
	noCacheClient.Timeout = time.Second
	noCache, err := NewConnector(Config{
		TenantID:  "tenant-a",
		Provider:  ProviderAWS,
		AccountID: "acct-1",
		Region:    "us-east-1",
		Endpoint:  noCacheSrv.URL,
		Credential: Credential{
			Principal: "cloud-reader",
			Token:     "fixture-token",
			Scopes:    RequiredReadScopes(ProviderAWS),
		},
		Client: noCacheClient,
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	empty, err := noCache.Pull(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Degraded || empty.Cached || len(empty.Metrics) != 0 {
		t.Fatalf("no-cache degraded snapshot = %+v", empty)
	}
}
