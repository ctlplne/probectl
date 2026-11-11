// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/pkg/sdk"
)

func TestPeeringCLIAndGeneratedSDKKeepExactTenantBoundInputsAndQualifiedOutput(t *testing.T) {
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		raw := `{"context_id":"22222222-2222-4222-8222-222222222222","interface_id":"33333333-3333-4333-8333-333333333333","peer_asn":4294967295,"ix_id":"9223372036854775807","ix_lan_id":"9007199254740993","direction":"inbound"}`
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/v1/flows/peering-estimate" || r.Header.Get("X-Probectl-Tenant") != tenant {
				t.Error("peering client changed tenant or route")
			}
			var body sdk.PeeringEstimateInput
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IxId != "9223372036854775807" || body.IxLanId != "9007199254740993" || body.PeerAsn != 4294967295 {
				t.Error("peering client narrowed full identity", body, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"preview":true,"reason":"partial_routing_evidence","coverage":{"complete_observed_inputs":true,"complete_routing_classification":false},"bytes":{"unavailable_transit":"184467440737095516160000"},"known_eligible_p95":{"bits_per_second_numerator":"101000000000","bits_per_second_denominator":"1"}}`)
		})
		tls := httptest.NewTLSServer(handler)
		client := sdk.NewClient(tls.URL, sdk.WithHTTPClient(tls.Client()), sdk.WithTenant(tenant))
		var input sdk.PeeringEstimateInput
		if err := json.Unmarshal([]byte(raw), &input); err != nil {
			t.Fatal(err)
		}
		out, err := client.EstimateFlowPeering(t.Context(), sdk.EstimateFlowPeeringRequest{Body: &input})
		if err != nil || out.KnownEligibleP95.BitsPerSecondNumerator != "101000000000" || out.Bytes["unavailable_transit"] != "184467440737095516160000" {
			t.Fatal("generated peering SDK lost exact qualified output", out, err)
		}
		tls.Close()
		local := httptest.NewServer(handler)
		stdout, stderr, code := run(t, local, "--tenant", tenant, "--json", "peering", "estimate", "--body", raw)
		local.Close()
		if code != 0 || !strings.Contains(stdout, "184467440737095516160000") || !strings.Contains(stdout, "partial_routing_evidence") {
			t.Fatal("named peering CLI lost exact qualified output", code, stdout, stderr)
		}
	}
}
