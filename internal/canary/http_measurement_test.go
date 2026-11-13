// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary_test

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/canary"
)

func TestHTTPPrimaryResponseFactsKeepObservedStatusAndStayOffOrdinaryBus(t *testing.T) {
	for _, code := range []int{http.StatusOK, http.StatusServiceUnavailable, 777} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
		t.Cleanup(server.Close)
		ca := trustServerCert(t, server)
		result := runCanary(t, server.URL, map[string]string{"ca_file": ca})
		if result.HTTP == nil || result.HTTP.StatusCode != code || !result.HTTP.TLSVerified || !result.HTTP.SameOrigin || result.Success != (code == http.StatusOK) {
			t.Fatal("primary response facts changed the observed status, trust or configured origin", code, result.HTTP, result.Success)
		}
		body, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(body, &fields); err != nil {
			t.Fatal(err)
		}
		if fields["HTTP"] != nil || fields["http"] != nil {
			t.Fatal("collector-only response facts were serialized onto the ordinary result bus")
		}
		var injected canary.Result
		if err := json.Unmarshal([]byte(`{"HTTP":{"StatusCode":503,"TLSVerified":true,"SameOrigin":true},"http":{"StatusCode":503}}`), &injected); err != nil || injected.HTTP != nil {
			t.Fatal("ordinary bus JSON supplied primary response authority", injected.HTTP, err)
		}
	}
}

func TestHTTPPostureHandshakeCannotCreatePrimaryResponseFacts(t *testing.T) {
	t.Setenv("GODEBUG", "tls10server=1,tls11server=1")
	server := startTLSServer(t, &tls.Config{MaxVersion: tls.VersionTLS11})
	ca := trustServerCert(t, server)
	result := runCanary(t, server.URL, map[string]string{"ca_file": ca})
	if result.Success || result.HTTP != nil || result.Attributes["tls.protocol.version"] != "1.1" || result.Attributes["probectl.tls.server.verified"] != "true" {
		t.Fatal("trusted record-only posture became a completed request", result.Success, result.HTTP, result.Attributes["tls.protocol.version"])
	}
}
