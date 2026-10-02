// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"net/http"
	"reflect"
	"testing"
	"time"
)

// TestHardenedClientsHonorProxyEnv is the PLAT-07 regression: the hardened and
// guarded HTTP transports set no Proxy, so outbound integrations (SIEM, on-call/
// ITSM, AI, secret managers, S3, CMDB, feeds) could not traverse a mandatory
// egress proxy and failed with direct dials. Both transports must now resolve a
// proxy from the environment (http.ProxyFromEnvironment, which honors
// HTTPS_PROXY/HTTP_PROXY/NO_PROXY and is a no-op when unset).
//
// The assertion is structural — that Proxy is wired to ProxyFromEnvironment —
// because http.ProxyFromEnvironment caches the environment once per process, so
// an env-driven functional check would be order-dependent and flaky.
func TestHardenedClientsHonorProxyEnv(t *testing.T) {
	want := reflect.ValueOf(http.ProxyFromEnvironment).Pointer()
	for _, tc := range []struct {
		name   string
		client *http.Client
	}{
		{"hardened", HardenedHTTPClient(5 * time.Second)},
		{"guarded", GuardedHTTPClient(5 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, ok := tc.client.Transport.(*http.Transport)
			if !ok {
				t.Fatalf("transport is %T, want *http.Transport", tc.client.Transport)
			}
			if tr.Proxy == nil {
				t.Fatal("transport has no Proxy func: a mandatory egress proxy (HTTPS_PROXY) is ignored (PLAT-07)")
			}
			if got := reflect.ValueOf(tr.Proxy).Pointer(); got != want {
				t.Fatal("transport.Proxy is not http.ProxyFromEnvironment, so HTTPS_PROXY/NO_PROXY are not honored (PLAT-07)")
			}
		})
	}
}
