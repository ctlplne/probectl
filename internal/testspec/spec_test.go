// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testspec

import (
	"strings"
	"testing"
)

func TestCleanDefaultsAndNormalization(t *testing.T) {
	s, err := Clean(Spec{Name: "edge http", Type: "HTTP", Target: " https://api.example.com "})
	if err != nil {
		t.Fatal(err)
	}
	if s.IntervalSeconds != DefaultIntervalSeconds || s.TimeoutSeconds != DefaultTimeoutSeconds {
		t.Errorf("defaults not applied: %+v", s)
	}
	if s.Type != "http" {
		t.Errorf("type not lowercased: %q", s.Type)
	}
	if s.Target != "https://api.example.com" {
		t.Errorf("target not trimmed: %q", s.Target)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]Spec{
		"no name":          {Type: "icmp", Target: "x"},
		"bad type":         {Name: "n", Type: "ping", Target: "x"},
		"no target":        {Name: "n", Type: "http"},
		"interval too big": {Name: "n", Type: "icmp", Target: "x", IntervalSeconds: 999999},
		"timeout too big":  {Name: "n", Type: "icmp", Target: "x", TimeoutSeconds: 9999},
	}
	for name, s := range cases {
		if _, err := Clean(s); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestNoopNeedsNoTarget(t *testing.T) {
	if _, err := Clean(Spec{Name: "heartbeat", Type: "noop"}); err != nil {
		t.Errorf("noop should be valid without a target: %v", err)
	}
}

func TestBrowserIsSchedulableType(t *testing.T) {
	s, err := Clean(Spec{Name: "login", Type: "BROWSER", Target: "https://app.example/login"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Type != "browser" {
		t.Fatalf("type = %q, want browser", s.Type)
	}
}

func TestTypesSorted(t *testing.T) {
	got := Types()
	if len(got) != len(ValidTypes) {
		t.Errorf("Types() = %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Errorf("Types() not sorted: %v", got)
		}
	}
}

func TestPathChangeOptionsValidationAndRetainedDefaults(t *testing.T) {
	for _, tc := range []struct {
		name       string
		params     map[string]string
		wantReject string
		wantNotify bool
		wantMS     float64
	}{
		{"omitted", nil, "", true, DefaultPathChangeLatencyMS},
		{"disabled and minimum", map[string]string{PathChangeAlertsParam: "false", PathChangeLatencyParam: "1"}, "", false, 1},
		{"enabled and maximum", map[string]string{PathChangeAlertsParam: "true", PathChangeLatencyParam: "60000"}, "", true, 60000},
		{"invalid toggle", map[string]string{PathChangeAlertsParam: "yes"}, PathChangeAlertsParam, true, DefaultPathChangeLatencyMS},
		{"empty latency", map[string]string{PathChangeLatencyParam: ""}, PathChangeLatencyParam, true, DefaultPathChangeLatencyMS},
		{"fractional latency", map[string]string{PathChangeLatencyParam: "1.5"}, PathChangeLatencyParam, true, DefaultPathChangeLatencyMS},
		{"below minimum", map[string]string{PathChangeLatencyParam: "0"}, PathChangeLatencyParam, true, DefaultPathChangeLatencyMS},
		{"above maximum", map[string]string{PathChangeAlertsParam: "false", PathChangeLatencyParam: "60001"}, PathChangeLatencyParam, false, DefaultPathChangeLatencyMS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Clean(Spec{Name: "edge path", Type: "icmp", Target: "192.0.2.1", Params: tc.params})
			if tc.wantReject == "" && err != nil || tc.wantReject != "" && (err == nil || !strings.Contains(err.Error(), tc.wantReject)) {
				t.Fatalf("Clean returned %v, expected rejection for %q", err, tc.wantReject)
			}
			// Callers also read retained and imported definitions directly.
			// Older malformed settings use the existing safe defaults.
			notify, latency := PathChangeOptions(tc.params)
			if notify != tc.wantNotify || latency != tc.wantMS {
				t.Fatalf("PathChangeOptions = (%t, %g), want (%t, %g)", notify, latency, tc.wantNotify, tc.wantMS)
			}
		})
	}
}
