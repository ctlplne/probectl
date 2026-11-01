// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package path

import (
	"net"
	"net/url"
	"strings"
)

// TargetHost is the exact destination key used by the control-plane path
// store. A test's routing-context binding must use this same key: path rounds
// are tenant+destination scoped until agent-dispatched tracing is available.
func TargetHost(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			if h := u.Hostname(); h != "" {
				return h
			}
		}
	}
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		return h
	}
	return target
}
