// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsupport

import "testing"

// A render is retried only when expected text is missing, nothing forbidden
// rendered, it performed no Steps (a retry must not act twice), and Chromium
// reported net::ERR_NETWORK_CHANGED.
func TestShouldRetryRenderOnlyReadOnlyNetworkChange(t *testing.T) {
	changed := []string{"request failed: https://localhost:18443/v1/me net::ERR_NETWORK_CHANGED"}
	other := []string{"request failed: https://localhost:18443/v1/me net::ERR_CONNECTION_REFUSED"}
	failed := RenderResult{Missing: []string{"Device Globex"}}
	for _, tc := range []struct {
		name string
		spec RenderSpec
		res  RenderResult
		want bool
	}{
		{"read-only, network changed", RenderSpec{}, RenderResult{Missing: failed.Missing, Errors: changed}, true},
		{"read-only, other error", RenderSpec{}, RenderResult{Missing: failed.Missing, Errors: other}, false},
		{"steps, network changed", RenderSpec{Steps: []RenderStep{{}}}, RenderResult{Missing: failed.Missing, Errors: changed}, false},
		{"passed, network changed", RenderSpec{}, RenderResult{Errors: changed}, false},
		{"forbidden text present is never retried", RenderSpec{}, RenderResult{Missing: failed.Missing, Present: []string{"other tenant"}, Errors: changed}, false},
	} {
		if got := shouldRetryRender(tc.spec, tc.res); got != tc.want {
			t.Errorf("%s: shouldRetryRender = %v, want %v", tc.name, got, tc.want)
		}
	}
}
