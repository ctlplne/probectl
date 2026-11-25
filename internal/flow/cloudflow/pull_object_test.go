// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/secrets"
)

type fixtureObjectTransport func(*http.Request) (*http.Response, error)

func (f fixtureObjectTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func objectFixtureResponse(req *http.Request, body []byte) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Request: req, Header: make(http.Header),
		ContentLength: int64(len(body)), Body: io.NopCloser(bytes.NewReader(body))}
}

func objectFixtureResolver(t *testing.T, lookup func(string) string) *secrets.Resolver {
	t.Helper()
	r, err := secrets.NewResolver(time.Minute, secrets.NewEnvSource(lookup))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestCloudObjectPullStagesCompleteProviderReads(t *testing.T) {
	x := filepath.Join(t.TempDir(), "collector.yaml")
	if err := os.WriteFile(x, []byte(`apiVersion: probectl.io/flow-agent/v1
tenant_id: configured-tenant
agent_id: agent-read
bus:
  mode: nats
  brokers: [nats.example.test:4222]
netflow: {enabled: false}
ipfix: {enabled: false}
sflow: {enabled: false}
cloud_import:
  provider: gcp_vpc_flow_logs
  object:
    bucket: office-flow
    key: logs/latest.jsonl
    version: "1700000123"
    credential_ref: env:OAUTH_FLOW_READ
`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := flow.Load(x)
	if err != nil || loaded.CloudImport.Object == nil || loaded.CloudImport.Object.Bucket != "office-flow" || loaded.CloudImport.Path != "" {
		t.Fatal("standard collector configuration did not select the cloud object", err)
	}

	const token = "fixture-read-only-token"
	resolver := objectFixtureResolver(t, func(name string) string {
		if name == "AWS_FLOW_READ" {
			return `{"access_key_id":"FIXTUREACCESS0001","secret_access_key":"fixture-key-material","session_token":"fixture-sts"}`
		}
		if name == "OAUTH_FLOW_READ" {
			return token
		}
		return ""
	})
	for _, tc := range []struct {
		provider Provider
		object   flow.CloudObjectConfig
		fixture  string
		check    func(*testing.T, *http.Request)
	}{
		{ProviderAWSVPC, flow.CloudObjectConfig{Bucket: "office-flow", Region: "eu-west-1", ExpectedOwner: "111122223333",
			Key: "logs/a.log.gz", Version: "version+/1", CredentialRef: "env:AWS_FLOW_READ"}, "aws-vpc-flow.log", nil},
		{ProviderAzureNSG, flow.CloudObjectConfig{Account: "officeflow1", Bucket: "office-flow", Key: "logs/a +?.json",
			Version: "2025-11-30T00:00:00.0000000Z", CredentialRef: "env:OAUTH_FLOW_READ"}, "azure-nsg-flow.jsonl", func(t *testing.T, req *http.Request) {
			if req.URL.Host != "officeflow1.blob.core.windows.net" || req.URL.EscapedPath() != "/office-flow/logs/a%20+%3F.json" ||
				req.URL.Query().Get("versionid") != "2025-11-30T00:00:00.0000000Z" || req.Header.Get("X-Ms-Version") != "2023-11-03" {
				t.Fatal("Azure request changed the configured object scope", req.URL)
			}
		}},
		{ProviderGCPVPC, flow.CloudObjectConfig{Bucket: "office-flow", Key: "logs/a +?.json", Version: "1700000123", CredentialRef: "env:OAUTH_FLOW_READ"},
			"gcp-vpc-flow.jsonl", func(t *testing.T, req *http.Request) {
				if req.URL.Host != "storage.googleapis.com" || req.URL.EscapedPath() != "/download/storage/v1/b/office-flow/o/logs%2Fa%20+%3F.json" ||
					req.URL.Query().Get("generation") != "1700000123" || req.URL.Query().Get("alt") != "media" {
					t.Fatal("Cloud Storage request changed the configured object scope", req.URL)
				}
			}},
	} {
		t.Run(string(tc.provider), func(t *testing.T) {
			body := readFixture(t, tc.fixture)
			if tc.provider == ProviderAzureNSG {
				var multiline bytes.Buffer
				if err := json.Indent(&multiline, body, "", "  "); err != nil {
					t.Fatal(err)
				}
				body = multiline.Bytes()
			}
			transfer := newCloudObjectTransfer()
			transfer.copyS3 = func(_ context.Context, cfg objectstore.S3Config, object objectstore.S3ReadRevision, dst io.Writer, cap int64) (int64, error) {
				if tc.provider != ProviderAWSVPC || cfg.Endpoint != "https://s3.eu-west-1.amazonaws.com" || cfg.Bucket != "office-flow" ||
					cfg.AccessKey != "FIXTUREACCESS0001" || cfg.SessionToken != "fixture-sts" || object.Key != "logs/a.log.gz" ||
					object.Version != "version+/1" || object.ExpectedOwner != "111122223333" || object.ETag != "" || cap != maxPullBytes {
					t.Fatal("AWS request lost its scoped endpoint, credential, object or bound")
				}
				return io.Copy(dst, bytes.NewReader(body))
			}
			transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
				if tc.check == nil || req.URL.Scheme != "https" || req.Method != http.MethodGet || req.Header.Get("Authorization") != "Bearer "+token ||
					strings.Contains(req.URL.String(), token) {
					t.Fatal("provider request did not keep credentials in a read-only HTTPS header")
				}
				tc.check(t, req)
				return objectFixtureResponse(req, body), nil
			})
			em := &captureEmitter{}
			cfg := flow.CloudImportConfig{Provider: string(tc.provider), Object: &tc.object}
			n, malformed, err := transfer.pull(t.Context(), cfg, "configured-tenant", "agent-read", resolver, em)
			if n != 1 || malformed != 0 || len(em.recs) != 1 || err != nil || em.recs[0].TenantID != "configured-tenant" {
				t.Fatalf("pull did not publish exactly one configured-tenant observation: %d, %d, %+v, %v", n, malformed, em.recs, err)
			}
		})
	}

	cfg := loaded.CloudImport
	for _, bad := range []flow.CloudObjectConfig{
		{Bucket: "office-flow", Key: "../logs/latest.jsonl", CredentialRef: "env:OAUTH_FLOW_READ"},
		{Bucket: "https://fixture.invalid", Key: "logs/latest.jsonl", CredentialRef: "env:OAUTH_FLOW_READ"},
		{Bucket: "office-flow", Key: "logs/latest.jsonl", CredentialRef: "literal:" + token},
	} {
		if err := (flow.CloudImportConfig{Provider: cfg.Provider, Object: &bad}).Validate(); err == nil || strings.Contains(err.Error(), token) {
			t.Fatal("invalid object selection was accepted or printed credential data")
		}
	}
	t.Run("mutable S3 null version", func(t *testing.T) {
		cfg := flow.CloudImportConfig{Provider: string(ProviderAWSVPC), Object: &flow.CloudObjectConfig{
			Bucket: "office-flow", Region: "eu-west-1", ExpectedOwner: "111122223333",
			Key: "logs/a.log.gz", Version: "null", CredentialRef: "env:AWS_FLOW_READ",
		}}
		transfer := newCloudObjectTransfer()
		copies := 0
		transfer.copyS3 = func(context.Context, objectstore.S3Config, objectstore.S3ReadRevision, io.Writer, int64) (int64, error) {
			copies++
			return 0, nil
		}
		if _, _, err := transfer.pull(t.Context(), cfg, "configured-tenant", "agent-read", resolver, &captureEmitter{}); copies != 0 || err == nil {
			t.Fatalf("a mutable null version reached the S3 request: %d, %v", copies, err)
		}
	})
	valid := readFixture(t, "gcp-vpc-flow.jsonl")
	var gzipBody bytes.Buffer
	z := gzip.NewWriter(&gzipBody)
	if _, err := z.Write(bytes.Repeat(valid, 1001)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := gzipBody.Bytes()
	corrupt[len(corrupt)-8] ^= 1 // Corrupt the checksum after enough data to flush a batch.
	line := append(bytes.TrimSpace(valid), '\n')
	lateOverlongLine := append(bytes.Repeat(line, 1001), bytes.Repeat([]byte("x"), maxCloudLineBytes+1)...)
	for _, tc := range []struct {
		name  string
		alter func(*http.Response) *http.Response
	}{
		{"truncated body", func(res *http.Response) *http.Response { res.ContentLength++; return res }},
		{"oversized object", func(res *http.Response) *http.Response { res.ContentLength = maxPullBytes + 1; return res }},
		{"wrong generation", func(res *http.Response) *http.Response { res.Header.Set("X-Goog-Generation", "8"); return res }},
		{"bad gzip checksum", func(res *http.Response) *http.Response { return objectFixtureResponse(res.Request, corrupt) }},
		{"overlong final line after a full batch", func(res *http.Response) *http.Response {
			return objectFixtureResponse(res.Request, lateOverlongLine)
		}},
		{"redirect", func(res *http.Response) *http.Response {
			res.StatusCode = http.StatusTemporaryRedirect
			res.Header.Set("Location", "https://storage.googleapis.com/download/storage/v1/b/other-tenant/o/secret")
			return res
		}},
		{"unauthorized", func(res *http.Response) *http.Response { res.StatusCode = http.StatusForbidden; return res }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			touched := 0
			transfer := newCloudObjectTransfer()
			transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
				touched++
				return tc.alter(objectFixtureResponse(req, valid)), nil
			})
			em := &captureEmitter{}
			n, _, err := transfer.pull(t.Context(), cfg, "a", "read", resolver, em)
			if n != 0 || len(em.recs) != 0 || touched != 1 || err == nil || strings.Contains(err.Error(), token) {
				t.Fatalf("an unsuccessful pull emitted, redirected, or logged credentials: %d, %d, %d, %v", n, len(em.recs), touched, err)
			}
		})
	}
	t.Run("invalid Azure VNet JSON after a full batch", func(t *testing.T) {
		const record = `{"category":"FlowLogFlowEvent","flowLogVersion":4,
			"targetResourceID":"/subscriptions/demo/resourceGroups/Fixture/providers/Microsoft.Network/virtualNetworks/Blue",
			"flowRecords":{"flows":[{"flowGroups":[{"flowTuples":["1782820800,10.0.0.4,192.0.2.12,49342,443,6,O,C,NX,5,100,0,0"]}]}]}}`
		const ending = `{"unexpected":`
		body := []byte(`{"records":[` + strings.Repeat(record+",", 257) + ending)
		transfer := newCloudObjectTransfer()
		transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
			return objectFixtureResponse(req, body), nil
		})
		cfg := flow.CloudImportConfig{Provider: string(ProviderAzureVNet), Object: &flow.CloudObjectConfig{
			Account: "officeflow1", Bucket: "office-flow", Key: "logs/PT1H.json", CredentialRef: "env:OAUTH_FLOW_READ",
		}}
		em := &captureEmitter{}
		if n, _, err := transfer.pull(t.Context(), cfg, "configured-tenant", "agent-read", resolver, em); n != 0 || len(em.recs) != 0 || err == nil {
			t.Fatalf("invalid JSON after complete batches published cloud observations: %d, %d, %v", n, len(em.recs), err)
		}
	})
	t.Run("incomplete Azure NSG export", func(t *testing.T) {
		var multiline bytes.Buffer
		if err := json.Indent(&multiline, bytes.TrimSpace(readFixture(t, "azure-nsg-flow.jsonl")), "", "  "); err != nil {
			t.Fatal(err)
		}
		body := multiline.Bytes()
		transfer := newCloudObjectTransfer()
		transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
			return objectFixtureResponse(req, body[:len(body)-1]), nil
		})
		cfg := flow.CloudImportConfig{Provider: string(ProviderAzureNSG), Object: &flow.CloudObjectConfig{
			Account: "officeflow1", Bucket: "office-flow", Key: "logs/PT1H.json", CredentialRef: "env:OAUTH_FLOW_READ",
		}}
		em := &captureEmitter{}
		if n, _, err := transfer.pull(t.Context(), cfg, "configured-tenant", "agent-read", resolver, em); n != 0 || len(em.recs) != 0 || err == nil {
			t.Fatalf("incomplete NSG object reached the emitter: %d, %d, %v", n, len(em.recs), err)
		}
	})
}
