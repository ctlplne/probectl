// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type reportDeadlineRoundTripper func(*http.Request) (*http.Response, error)

func (f reportDeadlineRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReportHTTPDeadlineKeepsCompleteOperationsAndIndependentTenantClients(t *testing.T) {
	for _, tenant := range []string{"a", "b"} {
		client := NewClient("https://reports.example", WithTenant(tenant), WithToken(tenant))
		client.HTTPClient.Transport = reportDeadlineRoundTripper(func(r *http.Request) (*http.Response, error) {
			deadline, ok := r.Context().Deadline()
			if !ok || time.Until(deadline) < 5*time.Minute || r.Header.Get("X-Probectl-Tenant") != tenant || r.Header.Get("Authorization") != "Bearer "+tenant {
				t.Fatal("complete report lost its separate deadline or caller identity")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(tenant)), ContentLength: 1}, nil
		})
		body, err := client.doRaw(t.Context(), http.MethodPost, "/v1/dashboard-reports", nil, nil)
		if err != nil || string(body) != tenant {
			t.Fatal("report generation lost its caller-specific response", err)
		}
		var output bytes.Buffer
		if written, err := client.DownloadDashboardReportArtifactTo(t.Context(), DownloadDashboardReportArtifactRequest{Id: "same-artifact"}, &output, 16); err != nil || written != 1 || output.String() != tenant {
			t.Fatal("streamed report lost its caller-specific response", err)
		}
		if client.HTTPClient.Timeout != 15*time.Second || client.reportHTTPClient(client.HTTPClient, http.MethodGet, "/v1/me") != client.HTTPClient {
			t.Fatal("long report mutated the shared ordinary request client")
		}
	}
}

func TestReportHTTPDeadlinePreservesExplicitClientAndEarlierCallerDeadline(t *testing.T) {
	for _, custom := range []bool{false, true} {
		client := NewClient("https://reports.example")
		if custom {
			client = NewClient("https://reports.example", WithHTTPClient(&http.Client{Timeout: 2 * time.Second}))
		}
		deadline := time.Now().Add(time.Second)
		ctx, cancel := context.WithDeadline(t.Context(), deadline)
		client.HTTPClient.Transport = reportDeadlineRoundTripper(func(r *http.Request) (*http.Response, error) {
			if actual, ok := r.Context().Deadline(); !ok || !actual.Equal(deadline) {
				t.Fatal("report default extended the caller's earlier deadline")
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}"))}, nil
		})
		_, err := client.GenerateDashboardReport(ctx, GenerateDashboardReportRequest{})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if custom && client.reportHTTPClient(client.HTTPClient, http.MethodPost, "/v1/dashboard-reports") != client.HTTPClient {
			t.Fatal("report operation replaced an explicit caller client")
		}
	}
}
