// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/threat"
)

// DPR-075: "which detections are live, at which thresholds" is an API answer
// (merged defaults + overlay, sorted, with enabled/suppress/thresholds), not a
// startup log line; without an NDR engine the surface says so instead of
// pretending an empty rule set is in force.
func TestThreatRulesSurfaceReportsTheLiveRuleSet(t *testing.T) {
	off := false
	rules := []threat.DetectionRule{
		{ID: "ndr-dns-dga-default", Version: 2, Kind: threat.KindDNSDGA, Name: "DGA (off)", Severity: "warning", BaseConfidence: 50, Suppress: time.Hour, Enabled: &off},
		{ID: "ndr-beaconing-default", Version: 2, Kind: threat.KindBeaconing, Name: "Periodic beaconing (tuned)", Severity: "warning",
			BaseConfidence: 45, Suppress: 30 * time.Minute, Thresholds: map[string]float64{"min_samples": 8, "internal_penalty": 30}},
	}
	srv := testServer(fakePinger{}).WithThreatRules(func() []threat.DetectionRule { return rules }, "/etc/probectl/ndr-rules")
	rec := do(srv, http.MethodGet, "/v1/threat/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Running    bool             `json:"rules_running"`
		OverlayDir string           `json:"overlay_dir"`
		Rules      []ThreatRuleView `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || resp.OverlayDir != "/etc/probectl/ndr-rules" || len(resp.Rules) != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Rules[0].ID != "ndr-beaconing-default" || resp.Rules[1].ID != "ndr-dns-dga-default" {
		t.Fatalf("rules must be sorted by id: %+v", resp.Rules)
	}
	b := resp.Rules[0]
	if !b.Enabled || b.Version != 2 || b.Kind != "beaconing" || b.Suppress != "30m0s" || b.Thresholds["internal_penalty"] != 30 {
		t.Fatalf("beaconing view = %+v", b)
	}
	if resp.Rules[1].Enabled {
		t.Fatal("a rule with enabled: false must be reported off")
	}

	rec = do(testServer(fakePinger{}), http.MethodGet, "/v1/threat/rules")
	if rec.Code != http.StatusOK {
		t.Fatalf("status without NDR = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Running || len(resp.Rules) != 0 {
		t.Fatalf("without an NDR engine the surface must report rules_running=false and no rules: %+v", resp)
	}
}
