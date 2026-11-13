// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"net/url"
	"testing"
)

func TestHTTPProbeOriginMatchesActualSchemeHostAndPort(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		want        bool
	}{
		{"https://example.test", "https://example.test:443/health", true},
		{"http://example.test", "http://example.test:80/health", true},
		{"https://ignored-user@EXAMPLE.TEST/start", "https://example.test/finish", true},
		{"https://example.test:8443", "https://example.test:9443", false},
		{"http://example.test", "https://example.test", false},
		{"https://example.test", "https://different.test", false},
		{"", "", false},
	} {
		left, err := url.Parse(tc.left)
		if err != nil {
			t.Fatal(err)
		}
		right, err := url.Parse(tc.right)
		if err != nil {
			t.Fatal(err)
		}
		if sameHTTPProbeOrigin(left, right) != tc.want {
			t.Fatal("response origin did not preserve actual scheme, host and effective port", tc)
		}
	}
	if sameHTTPProbeOrigin(nil, &url.URL{}) || sameHTTPProbeOrigin(&url.URL{}, nil) {
		t.Fatal("missing primary request origin was treated as a match")
	}
}
