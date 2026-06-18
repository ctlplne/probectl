// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/config"
)

// RED-001: dev auth may only ever bind loopback. Wildcards and empty hosts
// bind every interface and must be refused.
func TestLoopbackOnly(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":  true,
		"localhost:8080":  true,
		"[::1]:8080":      true,
		":8080":           false, // empty host = all interfaces
		"0.0.0.0:8080":    false,
		"[::]:8080":       false,
		"10.0.0.5:8080":   false,
		"192.168.1.2:443": false,
		"example.com:443": false,
		"127.0.0.1":       false, // no port = malformed for our listener
	}
	for addr, want := range cases {
		if got := loopbackOnly(addr); got != want {
			t.Errorf("loopbackOnly(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestValidateDevAuthMode(t *testing.T) {
	t.Setenv("PROBECTL_DEV_AUTH_ACK", "")
	orig := devAuthAvailable
	t.Cleanup(func() { devAuthAvailable = orig })

	devAuthAvailable = func() bool { return false }
	if err := validateDevAuthMode(&config.Config{AuthMode: "session", HTTPAddr: "0.0.0.0:8080"}); err != nil {
		t.Fatalf("session auth should not run dev gate: %v", err)
	}
	if err := validateDevAuthMode(&config.Config{AuthMode: "dev", HTTPAddr: "127.0.0.1:8080"}); err == nil || !strings.Contains(err.Error(), "not compiled") {
		t.Fatalf("release build should refuse dev auth before any weaker checks, got %v", err)
	}

	devAuthAvailable = func() bool { return true }
	if err := validateDevAuthMode(&config.Config{AuthMode: "dev", HTTPAddr: "127.0.0.1:8080"}); err == nil || !strings.Contains(err.Error(), "PROBECTL_DEV_AUTH_ACK") {
		t.Fatalf("dev auth without explicit ack should fail closed, got %v", err)
	}

	t.Setenv("PROBECTL_DEV_AUTH_ACK", "i-understand")
	if err := validateDevAuthMode(&config.Config{AuthMode: "dev", HTTPAddr: "0.0.0.0:8080"}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("dev auth on wildcard bind should fail closed, got %v", err)
	}
	if err := validateDevAuthMode(&config.Config{AuthMode: "dev", HTTPAddr: "127.0.0.1:8080"}); err != nil {
		t.Fatalf("dev auth with compiled hook, explicit ack, and loopback should pass: %v", err)
	}
}
