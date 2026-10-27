// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOpenSLOExportPreservesYAML(t *testing.T) {
	for _, payload := range []string{"apiVersion: openslo/v1\nkind: SLO\n---\napiVersion: openslo/v1\nkind: SLO\n", ""} {
		for _, jsonOut := range []bool{false, true} {
			c := &client{cfg: Config{BaseURL: "https://probectl.example"}, hc: &http.Client{Transport: cliBodyLimitRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/yaml; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(payload))}, nil
			})}}
			var value any
			if err := c.do(http.MethodGet, "/v1/slos/openslo", nil, &value); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if code := printGeneric(&out, value, jsonOut, http.MethodGet); code != 0 || out.String() != payload {
				t.Fatalf("json=%t got %q, want exact %q", jsonOut, out.String(), payload)
			}
		}
	}
}

func TestOpenSLOExportKeepsJSONAndErrors(t *testing.T) {
	for _, tc := range []struct {
		status    int
		body      string
		wantError bool
	}{
		{http.StatusOK, `{"slo_running":false}`, false},
		{http.StatusForbidden, `{"error":{"code":"forbidden","message":"metrics.read required"}}`, true},
	} {
		c := cliBodyLimitClient(tc.status, func() io.ReadCloser { return io.NopCloser(strings.NewReader(tc.body)) })
		var out any
		err := c.do(http.MethodGet, "/v1/slos/openslo", nil, &out)
		if (err != nil) != tc.wantError {
			t.Fatalf("status=%d err=%v", tc.status, err)
		}
		if !tc.wantError && out.(map[string]any)["slo_running"] != false {
			t.Fatalf("JSON response changed: %#v", out)
		}
	}
}
