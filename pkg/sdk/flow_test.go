// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFlowTopTalkersPreservesRepeatedFilters(t *testing.T) {
	filters := []string{"src:10.0.0.1", "protocol:ipfix"}
	client := NewClient("https://probectl.example", WithHTTPClient(&http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if got := r.URL.Query()["filter"]; len(got) != 2 ||
				got[0] != filters[0] || got[1] != filters[1] {
				t.Fatalf("filter query = %v, want %v", got, filters)
			}
			if got := r.URL.Query().Get("by"); got != "dst_country" {
				t.Fatalf("by query = %q", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"items":[]}`)),
			}, nil
		}),
	}))

	if _, err := client.FlowTopTalkers(context.Background(), FlowTopTalkersRequest{
		By:     String("dst_country"),
		Filter: &filters,
	}); err != nil {
		t.Fatalf("FlowTopTalkers: %v", err)
	}
}
