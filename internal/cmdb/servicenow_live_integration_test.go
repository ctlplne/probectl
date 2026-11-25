// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && servicenow_live

package cmdb

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestServiceNowLiveCredentialScope runs the same source-boundary check
// against an operator-authorized, read-only ServiceNow fixture over TLS.
func TestServiceNowLiveCredentialScope(t *testing.T) {
	endpoint, err := url.Parse(os.Getenv("PROBECTL_CMDB_URL"))
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" || endpoint.ForceQuery ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.RawFragment != "" {
		t.Fatal("live ServiceNow proof requires a bare HTTPS origin")
	}
	secret := os.Getenv("PROBECTL_CMDB_SECRET")
	user, password, ok := strings.Cut(secret, ":")
	if !ok || user == "" || password == "" {
		t.Fatal("the read-only ServiceNow test credential is required in the environment")
	}
	owner := tenancy.ID(os.Getenv("PROBECTL_CMDB_SERVICENOW_TENANT_ID"))
	if _, err := lookupTenant(tenancy.WithTenant(t.Context(), owner)); err != nil {
		t.Fatal("the configured ServiceNow owner must be a canonical tenant UUID")
	}
	key := CanonicalKey(os.Getenv("PROBECTL_TEST_SERVICENOW_CI_KEY"))
	expected := strings.TrimSpace(os.Getenv("PROBECTL_TEST_SERVICENOW_CI_ID"))
	if key == "" || expected == "" {
		t.Fatal("supply the lookup key and ID for a unique, authorized inventory fixture")
	}
	sibling := tenancy.ID(netBoxTenantB)
	if owner == sibling {
		sibling = netBoxTenantA
	}
	provider := NewServiceNow(endpoint.String(), os.Getenv("PROBECTL_CMDB_TABLE"), secret, owner)
	underlying := provider.client.Transport
	if closer, ok := underlying.(interface{ CloseIdleConnections() }); ok {
		t.Cleanup(closer.CloseIdleConnections)
	}
	var calls atomic.Int64
	provider.client.Transport = serviceNowLiveTransport{
		RoundTripper: underlying, host: endpoint.Host,
		path: "/api/now/table/" + url.PathEscape(provider.table), calls: &calls,
	}
	checkServiceNowCredentialScope(t, provider, owner, sibling, key, expected, &calls)
	t.Logf("verified ServiceNow Table API TLS GETs: owner %d, sibling 0, warm owner 0", calls.Load())
}

type serviceNowLiveTransport struct {
	http.RoundTripper
	host, path string
	calls      *atomic.Int64
}

func (transport serviceNowLiveTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	if request.Method != http.MethodGet || request.URL.Scheme != "https" || request.URL.Host != transport.host ||
		request.URL.EscapedPath() != transport.path {
		return nil, errors.New("live ServiceNow proof allows only reads from the authorized Table API")
	}
	response, err := transport.RoundTripper.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
		_ = response.Body.Close()
		return nil, errors.New("ServiceNow response must carry verified TLS")
	}
	return response, nil
}
