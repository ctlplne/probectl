// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/imfeelingtheagi/probectl/pkg/sdk"
)

func TestListTestsExampleUsesGeneratedSDK(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/tests" {
			t.Fatalf("path = %s, want /v1/tests", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "50" {
			t.Fatalf("limit query = %q, want 50", got)
		}
		if got := r.Header.Get("X-Probectl-Tenant"); got != "tenant-a" {
			t.Fatalf("tenant header = %q, want tenant-a", got)
		}
		var body bytes.Buffer
		_ = json.NewEncoder(&body).Encode(sdk.TestList{
			Items: []sdk.Test{{
				Id:       "018f7a3a-5f38-7cc1-bf69-8e8f62a6d2b0",
				TenantId: "tenant-a",
				Name:     "checkout",
				Type:     "http",
			}},
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(&body),
			Request:    r,
		}, nil
	})

	client := sdk.NewClient(
		"https://control.example",
		sdk.WithTenant("tenant-a"),
		sdk.WithHTTPClient(&http.Client{Transport: transport}),
	)
	tests, err := client.ListTests(context.Background(), sdk.ListTestsRequest{Limit: sdk.Int(50)})
	if err != nil {
		t.Fatalf("ListTests: %v", err)
	}
	if len(tests.Items) != 1 || tests.Items[0].Name != "checkout" {
		t.Fatalf("decoded tests = %+v", tests.Items)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
