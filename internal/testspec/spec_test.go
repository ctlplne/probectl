// SPDX-License-Identifier: LicenseRef-probectl-TBD

package testspec

import "testing"

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
