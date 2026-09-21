// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestCurrentEffectiveIdentity(t *testing.T) {
	got := currentEffectiveIdentity()
	if got.UID != os.Geteuid() || got.GID != os.Getegid() {
		t.Fatalf("identity = %+v, want uid=%d gid=%d", got, os.Geteuid(), os.Getegid())
	}
}

func TestQueryClickHouseRawPinsNumericJSON64BitIntegers(t *testing.T) {
	var gotQuery url.Values
	var gotBody string
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotQuery = r.URL.Query()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		gotBody = string(body)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{\"start_time_unix_nano\":1723377600123456789}\n")),
			Request:    r,
		}, nil
	})}

	parameters := url.Values{"param_trace": {"0123456789abcdef0123456789abcdef"}}
	body, err := queryClickHouseRaw(client, "https://clickhouse:8443", directTraceSQL, "tenant-a", parameters)
	if err != nil {
		t.Fatalf("queryClickHouseRaw: %v", err)
	}
	if got := gotQuery.Get(clickHouseJSONIntegerSetting); got != "0" {
		t.Fatalf("%s = %q, want 0", clickHouseJSONIntegerSetting, got)
	}
	if got := gotQuery.Get("SQL_probectl_tenant"); got != "tenant-a" {
		t.Fatalf("SQL_probectl_tenant = %q, want tenant-a", got)
	}
	if got := gotQuery.Get("param_trace"); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("param_trace = %q", got)
	}
	if gotBody != directTraceSQL {
		t.Fatalf("query body = %q, want canonical SQL", gotBody)
	}
	if string(body) != "{\"start_time_unix_nano\":1723377600123456789}\n" {
		t.Fatalf("response body = %q", body)
	}
}

func TestValidateDirectPrometheusReturnsSignedSampleTime(t *testing.T) {
	const marker = "0123456789abcdef0123456789abcdef"
	const tenant = "aaaaaaaa-0000-4000-8000-000000000001"
	body := []byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"probectl_otlp_completeness_product_marker","marker":"` + marker + `","service_name":"completeness-` + marker + `","tenant_id":"` + tenant + `"},"value":[1787255481.178,"84001"]}]}}`)

	got, err := validateDirectPrometheus(body, tenant, marker, productMetricValueA)
	if err != nil {
		t.Fatalf("validateDirectPrometheus: %v", err)
	}
	want := time.Unix(1787255481, 178000000).UTC()
	if got.Sub(want) > time.Microsecond || want.Sub(got) > time.Microsecond {
		t.Fatalf("sample time = %s, want %s", got, want)
	}
}

func TestWriteProductArtifactCreatesNewRootedFile(t *testing.T) {
	root := t.TempDir()
	if err := writeProductArtifact(root, "product/tenant/metrics.pb", []byte("evidence")); err != nil {
		t.Fatalf("writeProductArtifact: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "product", "tenant", "metrics.pb"))
	if err != nil || string(got) != "evidence" {
		t.Fatalf("artifact = %q, %v", got, err)
	}
	if err := writeProductArtifact(root, "product/tenant/metrics.pb", []byte("replacement")); err == nil {
		t.Fatal("writeProductArtifact reused an existing evidence target")
	}
}

func TestWriteProductArtifactRejectsSymlinkedIntermediate(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "product")); err != nil {
		t.Fatal(err)
	}
	if err := writeProductArtifact(root, "product/tenant/metrics.pb", []byte("escape")); err == nil {
		t.Fatal("writeProductArtifact accepted a symlinked parent")
	}
	if _, err := os.Lstat(filepath.Join(outside, "tenant", "metrics.pb")); !os.IsNotExist(err) {
		t.Fatalf("outside target was touched: %v", err)
	}
}

func TestWriteProductArtifactRejectsSymlinkedFinalTarget(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "product", "tenant")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.pb")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(parent, "metrics.pb")); err != nil {
		t.Fatal(err)
	}
	if err := writeProductArtifact(root, "product/tenant/metrics.pb", []byte("replacement")); err == nil {
		t.Fatal("writeProductArtifact accepted a symlinked final target")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "unchanged" {
		t.Fatalf("outside target = %q, %v", got, err)
	}
}
