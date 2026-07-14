// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/promapi"
)

func TestRunDryRunParsesCloudMetrics(t *testing.T) {
	var out bytes.Buffer
	raw := `{"namespace":"AWS/EC2","metric_name":"NetworkIn","timestamp":"2026-06-30T12:00:00Z","value":1}`
	err := run([]string{
		"-provider", "aws_cloudwatch_export",
		"-tenant", "tenant-a",
		"-url", "https://probectl.example",
		"-dry-run",
	}, func(string) string { return "" }, strings.NewReader(raw), &out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "validated 1 cloud metric samples") {
		t.Fatalf("out = %q", out.String())
	}
}

func TestRunPostsRemoteWriteToProbectlAPI(t *testing.T) {
	var sawTenant, sawMetric bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/prometheus/write" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if r.Header.Get("X-Probectl-Tenant") == "tenant-a" {
			sawTenant = true
		}
		body, _ := io.ReadAll(r.Body)
		series, err := promapi.DecodeRemoteWrite(body, "tenant-a", promapi.WriteLimits{})
		if err != nil {
			t.Fatalf("decode remote-write: %v", err)
		}
		if len(series) == 1 && series[0].Metric == "probectl_cloud_aws_networkin" && series[0].Labels["tenant_id"] == "tenant-a" {
			sawMetric = true
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	var out bytes.Buffer
	raw := `{"namespace":"AWS/EC2","metric_name":"NetworkIn","timestamp":"2026-06-30T12:00:00Z","value":1}`
	err := run([]string{
		"-provider", "aws_cloudwatch_export",
		"-tenant", "tenant-a",
		"-url", srv.URL,
	}, func(string) string { return "" }, strings.NewReader(raw), &out)
	if err != nil {
		t.Fatal(err)
	}
	if !sawTenant || !sawMetric {
		t.Fatalf("sawTenant=%t sawMetric=%t out=%q", sawTenant, sawMetric, out.String())
	}
}
