// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/entity"
)

func TestPathHealthNativeMetadataPreservesOriginalNumbersAndFullSourceRedaction(t *testing.T) {
	const id = "41111111-1111-4111-8111-111111111111"
	const card = "4111111111111111"
	value := pathHealthResult{TestID: id, ContextID: id, Items: []pathEntityHop{{IP: "10.42.0.2", Resolution: entity.Resolution{Scope: entity.Scope{TenantID: id, ContextID: id}, Status: entity.Resolved, EntityID: id},
		Health: &pathInterfaceHealth{ContextID: id, InterfaceID: id, DeviceID: id, SourceRef: card, AgentID: "operator@example.test", PhysicalMaxBPS: card, Counters: []pathHealthCounter{
			{Metric: pathHealthMetricNames[0], Value: card, PreviousValue: "9007199254740993", MinimumDelta: "1225000", RateNumerator: "9800000", RateDenominator: "1", RateUnit: "bits/s", RateKind: "exact_under_explicit_physical_bound", UtilizationNumerator: "98", UtilizationDenominator: "1", CaptureKey: strings.Repeat("4", 64), RawDigest: strings.Repeat("1", 64)},
			{Metric: pathHealthMetricNames[2], RateKind: "unavailable", RateUnit: "packets/s", Reason: "one_original_poll", Value: "0"},
		}}}}}
	raw, err := marshalNativePathHealth(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []ai.RedactionPolicy{ai.DefaultRedaction, {}} {
		var got pathHealthResult
		redacted := ai.NewEgressGate(nil, nil, policy).RedactForTenant(string(raw), id)
		if err := json.Unmarshal([]byte(redacted), &got); err != nil {
			t.Fatal(err)
		}
		health := got.Items[0].Health
		if got.TestID != id || health.ContextID != id || health.InterfaceID != id || health.PhysicalMaxBPS != card || health.Counters[0].Value != card || health.Counters[0].PreviousValue != "9007199254740993" || health.Counters[0].Metric != pathHealthMetricNames[0] || health.Counters[0].CaptureKey != strings.Repeat("4", 64) || health.Counters[1].Value != "0" {
			t.Fatal("canonical path IDs or typed original numeric/receipt metadata were rounded or redacted")
		}
		if health.SourceRef == card {
			t.Fatal("source text bypassed the always-on PAN floor")
		}
		if policy.MaskIPs && (got.Items[0].IP == value.Items[0].IP || health.AgentID == value.Items[0].Health.AgentID) {
			t.Fatal("arbitrary path/source text bypassed full default redaction")
		}
	}
	value.Items[0].Health.Counters[0].Metric = "untrusted.example.test"
	if _, err := marshalNativePathHealth(value); err == nil {
		t.Fatal("arbitrary source metric text received protected metadata encoding")
	}
}
