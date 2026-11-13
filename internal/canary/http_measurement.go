// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import (
	"net/url"
	"strings"
)

// HTTPMeasurement describes an actual final response to the primary probe
// request. A record-only posture handshake cannot produce it. It carries no
// URL, credentials, response body, tenant or provider attribution, and is not
// accepted from the ordinary result bus. Sender-authenticated evidence must
// bind it to the current test and original execution before verdict use.
type HTTPMeasurement struct {
	StatusCode  int
	TLSVerified bool
	SameOrigin  bool
}

func sameHTTPProbeOrigin(left, right *url.URL) bool {
	if left == nil || right == nil || left.Hostname() == "" || right.Hostname() == "" || !strings.EqualFold(left.Scheme, right.Scheme) || !strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	port := func(value *url.URL) string {
		if value.Port() != "" {
			return value.Port()
		}
		if strings.EqualFold(value.Scheme, "https") {
			return "443"
		}
		return "80"
	}
	return port(left) == port(right)
}
