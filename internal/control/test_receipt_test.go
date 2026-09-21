// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/store"
)

// TestTestReceiptIsTheAgentsCanaryEntry (DPR-065): the onboarding journey
// promises that registering a test hands back the exact canaries: entry with
// the server test_id; the API returned only the stored test. The receipt's
// config.canary must decode, strictly, as one entry of the agent's canaries
// list.
func TestTestReceiptIsTheAgentsCanaryEntry(t *testing.T) {
	stored := &store.Test{
		ID: "98bbc817-d2f0-403b-b067-fae2ca28de1e", TenantID: "t1", Name: "checkout", Type: "http",
		Target: "https://example.com/checkout", IntervalSeconds: 10, TimeoutSeconds: 5,
		Params: map[string]string{"method": "GET", "expect_status": "2xx,3xx"}, Enabled: true,
	}
	raw, err := json.Marshal(newTestReceipt(stored))
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		ID     string `json:"id"`
		Config struct {
			Canary map[string]any `json:"canary"`
		} `json:"config"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ID != stored.ID || receipt.Config.Canary["test_id"] != stored.ID {
		t.Fatalf("receipt does not carry the server test_id: %s", raw)
	}
	// Rendered as YAML it is exactly one canaries: entry the agent accepts.
	asYAML, err := yaml.Marshal(receipt.Config.Canary)
	if err != nil {
		t.Fatal(err)
	}
	var entry agent.CanaryConfig
	dec := yaml.NewDecoder(bytes.NewReader(asYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&entry); err != nil {
		t.Fatalf("the receipt is not an agent canaries: entry:\n%s\nerror: %v", asYAML, err)
	}
	if entry.Type != "http" || entry.Target != stored.Target || entry.TestID != stored.ID || entry.Params["expect_status"] != "2xx,3xx" {
		t.Fatalf("decoded entry = %+v", entry)
	}
	if entry.Interval.Std().Seconds() != 10 || entry.Timeout.Std().Seconds() != 5 {
		t.Fatalf("interval/timeout = %v/%v", entry.Interval.Std(), entry.Timeout.Std())
	}
}
