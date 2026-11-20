// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package siem_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type ownedSIEMTarget struct {
	base, index, user, password, ca string
	writer, writerPassword          string
	client                          *http.Client
}

func TestShippedSIEMAuditReachesOpenSearchWithExactTenantIdentity(t *testing.T) {
	target := stockOpenSearchTarget(t)
	stack := shipped.Start(t, shipped.Options{Name: "opensearch", TenantBand: 3, Env: map[string]string{
		"PROBECTL_SIEM_ENABLED":        "true",
		"PROBECTL_SIEM_PRESET":         "elastic",
		"PROBECTL_SIEM_AUTH_SCHEME":    "basic",
		"PROBECTL_SIEM_ENDPOINT":       target.base + "/" + target.index + "/_doc",
		"PROBECTL_SIEM_TOKEN":          target.writer + ":" + target.writerPassword,
		"PROBECTL_SIEM_POLL_INTERVAL":  "1s",
		"PROBECTL_SIEM_AUDIT_IDENTITY": "clear",
		"SSL_CERT_FILE":                target.ca,
	}})
	operator := stack.OnboardOperator(t, "root@msp-siem-wire.example")
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	owned := [2]struct {
		id, cookie, test string
		event            audit.Event
	}{}
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &owned[i]
		slug := "siem-receipt-" + stamp + "-" + strconv.Itoa(i)
		var result struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &result, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		lane.id, lane.cookie = result.ID, stack.SignIn(t, result.ID, email, slug)
		code, raw := stack.Do(t, lane.cookie, http.MethodPost, "/v1/tests", map[string]any{
			"name": slug, "type": "http", "target": stack.BaseURL + "/readyz",
			"interval_seconds": 60, "timeout_seconds": 5, "enabled": true,
			"params": map[string]string{"allow_private_targets": "true"},
		})
		var created struct{ ID string }
		if code != http.StatusCreated || json.Unmarshal(raw, &created) != nil || created.ID == "" {
			t.Fatalf("owned change failed with HTTP %d", code)
		}
		lane.test = created.ID
		code, raw = stack.Do(t, lane.cookie, http.MethodGet, "/v1/audit?limit=50", nil)
		var records struct{ Items []audit.Event }
		if code != http.StatusOK || json.Unmarshal(raw, &records) != nil {
			t.Fatalf("the tenant could not read its origin audit: HTTP %d", code)
		}
		for _, record := range records.Items {
			if record.Action == "test.create" && record.Target == lane.test {
				lane.event = record
			}
		}
		if lane.event.Hash == "" {
			t.Fatal("the owned API change has no source audit receipt")
		}
	}
	for i, lane := range owned {
		if code, _ := stack.Do(t, owned[1-i].cookie, http.MethodGet, "/v1/tests/"+lane.test, nil); code != http.StatusNotFound {
			t.Fatalf("a sibling tenant's API returned HTTP %d for a foreign test", code)
		}
		shipped.Await(t, "exact audit receipt at authenticated OpenSearch", 50*time.Second, func() bool {
			return target.receivedAudit(t, lane.id, lane.event)
		})
		code, status := stack.Do(t, lane.cookie, http.MethodGet, "/v1/siem/status", nil)
		checkSIEMReceiptPosture(t, target, code, status)
		token := stack.APIToken(t, lane.cookie, "diagnostics.read")
		var output json.RawMessage
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": token}, &output, "siem", "status")
		checkSIEMReceiptPosture(t, target, http.StatusOK, output)
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/admin", CAFile: stack.CAFile, TrustCertFiles: stack.TrustCerts(),
			Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lane.cookie}},
			Expect:  []string{"SIEM export posture"},
			Absent:  []string{target.writerPassword, target.password, target.index},
			Theme:   []string{"light", "dark"}[i],
		})
	}
}

func checkSIEMReceiptPosture(t *testing.T, target ownedSIEMTarget, code int, raw []byte) {
	t.Helper()
	var status struct {
		Configured bool
		Format     string
		TLS        bool `json:"endpoint_tls_configured"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &status) != nil || !status.Configured || !status.TLS || status.Format != "ecs" {
		t.Fatal("the tenant did not receive configured ECS and TLS posture", code)
	}
	for _, private := range []string{target.writerPassword, target.password, target.index} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("SIEM posture exposed private delivery configuration")
		}
	}
}

func stockOpenSearchTarget(t *testing.T) ownedSIEMTarget {
	t.Helper()
	out := ownedSIEMTarget{
		base:           strings.TrimRight(os.Getenv("PROBECTL_TEST_OPENSEARCH_URL"), "/"),
		user:           os.Getenv("PROBECTL_TEST_OPENSEARCH_USER"),
		password:       os.Getenv("PROBECTL_TEST_OPENSEARCH_PASSWORD"),
		writer:         os.Getenv("PROBECTL_TEST_OPENSEARCH_WRITER"),
		writerPassword: os.Getenv("PROBECTL_TEST_OPENSEARCH_WRITER_PASSWORD"),
		ca:             os.Getenv("PROBECTL_TEST_OPENSEARCH_CA_FILE"),
		index:          "probectl-siem-" + strconv.FormatInt(time.Now().UnixNano(), 36),
	}
	if out.base == "" && os.Getenv("PROBECTL_TEST_REQUIRE_OPENSEARCH") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_OPENSEARCH", "provide the owned OpenSearch TLS fixture for the SIEM delivery receipt")
	}
	parsed, err := url.Parse(out.base)
	if err != nil || parsed.Scheme != "https" || (parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "opensearch") ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		out.user == "" || out.password == "" || out.ca == "" || out.writer == "" || out.writer == out.user || out.writerPassword == "" {
		t.Fatal("the OpenSearch receipt requires an owned TLS endpoint and separate writer and admin credentials")
	}
	t.Setenv("PROBECTL_TEST_OPENSEARCH_PASSWORD", "")
	out.client, err = crypto.HardenedHTTPClientWithCAFile(5*time.Second, out.ca)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(out.client.CloseIdleConnections)
	code, _ := out.request(t, http.MethodPut, "/"+out.index, []byte(`{"settings":{"number_of_replicas":0}}`))
	if code != http.StatusOK && code != http.StatusCreated {
		t.Fatalf("the owned OpenSearch index could not be created: HTTP %d", code)
	}
	writer := out
	writer.user, writer.password = out.writer, out.writerPassword
	if code, _ := writer.request(t, http.MethodGet, "/"+out.index+"/_search", nil); code != http.StatusForbidden {
		t.Fatal("the OpenSearch writer can read the receipt index", code)
	}
	t.Cleanup(func() {
		req, err := http.NewRequest(http.MethodDelete, out.base+"/"+out.index, nil)
		if err != nil {
			t.Error(err)
			return
		}
		req.SetBasicAuth(out.user, out.password)
		res, err := out.client.Do(req)
		if err != nil {
			t.Error("could not remove the owned OpenSearch index", err)
			return
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusNotFound {
			t.Errorf("could not remove the owned OpenSearch index: HTTP %d", res.StatusCode)
		}
	})
	return out
}

func (target ownedSIEMTarget) receivedAudit(t *testing.T, tenant string, source audit.Event) bool {
	t.Helper()
	filters := []map[string]any{
		{"term": map[string]string{"labels.target.keyword": source.Target}},
		{"term": map[string]string{"event.action.keyword": source.Action}},
	}
	query, err := json.Marshal(map[string]any{"query": map[string]any{"bool": map[string]any{"filter": filters}}})
	if err != nil {
		t.Fatal(err)
	}
	code, raw := target.request(t, http.MethodPost, "/"+target.index+"/_search", query)
	var result struct {
		Hits struct {
			Hits []struct {
				Source struct {
					Organization struct{ ID string }
					Event        struct{ Action string }
					User         struct{ Name string }
					Labels       map[string]string
				} `json:"_source"`
			}
		}
	}
	if code != http.StatusOK || json.Unmarshal(raw, &result) != nil {
		t.Fatalf("the exact OpenSearch index query returned HTTP %d", code)
	}
	for _, hit := range result.Hits.Hits {
		got := hit.Source
		if got.Organization.ID != tenant || got.Event.Action != source.Action || got.User.Name != source.Actor ||
			got.Labels["audit_hash"] != source.Hash || got.Labels["audit_seq"] != strconv.FormatInt(source.Seq, 10) {
			t.Fatal("the forwarded audit changed its exact tenant, actor or original audit receipt")
		}
	}
	return len(result.Hits.Hits) >= 1
}

func (target ownedSIEMTarget) request(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, target.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(target.user, target.password)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := target.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}
