// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"net/http"
	"reflect"
	"testing"
)

// TestEnrollHTTPClientHonorsProxyEnv is the PLAT-07 regression for the agent
// enrollment client: it built its own transport with no Proxy, so an agent
// enrolling with a remote control plane could not traverse a mandatory egress
// proxy. The transport must resolve the proxy from the environment.
func TestEnrollHTTPClientHonorsProxyEnv(t *testing.T) {
	hc, err := enrollHTTPClient("", "")
	if err != nil {
		t.Fatalf("enrollHTTPClient: %v", err)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", hc.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("enrollment client has no Proxy func: HTTPS_PROXY is ignored (PLAT-07)")
	}
	if got, want := reflect.ValueOf(tr.Proxy).Pointer(), reflect.ValueOf(http.ProxyFromEnvironment).Pointer(); got != want {
		t.Fatal("enrollment client Proxy is not http.ProxyFromEnvironment (PLAT-07)")
	}
}
