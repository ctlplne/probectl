// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTestMutationsPreserveBooleanPresence(t *testing.T) {
	for _, enabled := range []*bool{nil, Bool(false), Bool(true)} {
		client := NewClient("https://probectl.example", WithTenant("tenant-a"), WithHTTPClient(&http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("X-Probectl-Tenant") != "tenant-a" {
					t.Fatal("tenant selector lost")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				value, present := body["enabled"]
				if present != (enabled != nil) || (enabled != nil && value != *enabled) {
					t.Fatalf("enabled presence/value = %v/%v, input %v", present, value, enabled)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"test-a"}`))}, nil
			}),
		}))
		body := &TestRequest{Name: "disabled test", Type: "http", Enabled: enabled}
		if _, err := client.CreateTest(context.Background(), CreateTestRequest{Body: body}); err != nil {
			t.Fatal(err)
		}
		if _, err := client.UpdateTest(context.Background(), UpdateTestRequest{Id: "test-a", Body: body}); err != nil {
			t.Fatal(err)
		}
	}
}
