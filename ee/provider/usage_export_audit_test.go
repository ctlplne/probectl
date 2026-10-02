// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"net/http"
	"testing"

	"github.com/ctlplne/probectl/internal/logging"
)

// TestProviderUsageExportIsAudited is the AUD-10 regression for the provider
// plane: a provider operator's cross-tenant usage EXPORT was served with no
// audit record. It must now produce exactly one provider.usage_exported event
// carrying the from-where (ip, hashed user agent, request id) and an outcome.
func TestProviderUsageExportIsAudited(t *testing.T) {
	const ua = "AUD10-ProviderUA/1.0"
	f, _, token := meteredFixture(t)

	req := newReq(http.MethodGet, "/provider/v1/usage/export?rollup=day", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", ua)
	// Simulate the server's request-id middleware (the handler is served in
	// isolation here); in production the middleware populates this.
	req = req.WithContext(logging.WithRequestID(req.Context(), "aud10-provider-req"))

	rec := doReq(f.h, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("usage export: want 200, got %d: %s", rec.Code, rec.Body)
	}

	if n := f.audit.count("provider.usage_exported"); n != 1 {
		t.Fatalf("AUD-10: provider usage export must be audited exactly once, got %d", n)
	}
	data := f.audit.lastData("provider.usage_exported")
	if data == nil {
		t.Fatal("AUD-10: no provider.usage_exported event recorded")
	}
	for _, field := range []string{"ip", "user_agent", "request_id", "outcome"} {
		if v, ok := data[field]; !ok || v == "" {
			t.Errorf("AUD-10: provider.usage_exported is missing %q (data=%v)", field, data)
		}
	}
	if data["outcome"] != "success" {
		t.Errorf("AUD-10: provider.usage_exported outcome = %v, want success", data["outcome"])
	}
	if data["request_id"] != "aud10-provider-req" {
		t.Errorf("AUD-10: provider.usage_exported request_id = %v, want the injected id", data["request_id"])
	}
	if uaVal, _ := data["user_agent"].(string); uaVal == ua {
		t.Error("AUD-10: provider.usage_exported stored the raw user agent instead of a hash")
	}
}
