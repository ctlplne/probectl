// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"net/http"
	"strings"
	"time"
)

// Report generation/downloads can outlive an ordinary API call. Adjust only
// the SDK-created default, without changing a caller's custom client, explicit
// timeout or the shared client used by simultaneous ordinary requests.
func (c *Client) reportHTTPClient(client *http.Client, method, path string) *http.Client {
	if c.defaultHTTPClient == nil || client != c.defaultHTTPClient || client.Timeout != 15*time.Second {
		return client
	}
	generation := method == http.MethodPost && path == "/v1/dashboard-reports"
	artifact, download := strings.CutPrefix(path, "/v1/dashboard-report-artifacts/")
	download = download && method == http.MethodGet && artifact != "" && !strings.Contains(artifact, "/")
	if !generation && !download {
		return client
	}
	selected := *client
	selected.Timeout = 5*time.Minute + 15*time.Second
	return &selected
}
