// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
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

func TestRunRefusesUnavailableDevAuthBeforeEnvelopeSetup(t *testing.T) {
	t.Setenv("PROBECTL_AUTH_MODE", "dev")
	t.Setenv("PROBECTL_ENVELOPE_KEY", "")
	t.Setenv("PROBECTL_ENVELOPE_KEY_FILE", "")
	t.Setenv("PROBECTL_ALLOW_KEYLESS_DEV", "")
	t.Setenv("PROBECTL_DATABASE_URL", "postgres://probectl:test-only@localhost:5432/probectl?sslmode=require")

	orig := devAuthAvailable
	devAuthAvailable = func() bool { return false }
	t.Cleanup(func() { devAuthAvailable = orig })

	err := run("serve")
	if err == nil {
		t.Fatal("release startup unexpectedly accepted unavailable dev auth")
	}
	if !strings.Contains(err.Error(), "not compiled into this binary") {
		t.Fatalf("release startup must reject unavailable dev auth before unrelated secret setup, got %v", err)
	}
	if strings.Contains(err.Error(), "envelope key") {
		t.Fatalf("release startup leaked past the authoritative dev-auth refusal: %v", err)
	}
}

// DPR-206: the "this binary has no dev auth" refusal used to live only inside
// validateDevAuthMode, which takes a loaded *config.Config — so a release binary
// asked for dev mode with nothing else configured refused with
// "load config: PROBECTL_DATABASE_URL is required". Correct to refuse, wrong
// thing to say: the operator fixes the database URL, restarts, and only then
// learns dev auth was never going to work in this build. CI's behavioral check
// caught exactly this and has been failing on it.
func TestReleaseBuildRefusesDevAuthBeforeAnyOtherConfig(t *testing.T) {
	orig := devAuthAvailable
	devAuthAvailable = func() bool { return false }
	t.Cleanup(func() { devAuthAvailable = orig })

	// Nothing else set at all: no database URL, no envelope key, no bind address.
	env := func(k string) string {
		if k == "PROBECTL_AUTH_MODE" {
			return "dev"
		}
		return ""
	}
	err := refuseDevAuthOnReleaseBuild(env)
	if err == nil {
		t.Fatal("a release binary must refuse dev auth even with nothing else configured")
	}
	if !strings.Contains(err.Error(), "not compiled into this binary") {
		t.Errorf("the refusal must name the real blocker, got %v", err)
	}
	if strings.Contains(err.Error(), "DATABASE_URL") {
		t.Errorf("the refusal must not be about unrelated config: %v", err)
	}

	// A build that HAS dev auth is not refused here — the remaining locks (the
	// typed acknowledgement and the loopback bind) need config and stay in
	// validateDevAuthMode.
	devAuthAvailable = func() bool { return true }
	if err := refuseDevAuthOnReleaseBuild(env); err != nil {
		t.Errorf("a devauth build must pass this gate and be judged by the other locks: %v", err)
	}

	// And any other auth mode is none of this gate's business.
	devAuthAvailable = func() bool { return false }
	if err := refuseDevAuthOnReleaseBuild(func(string) string { return "session" }); err != nil {
		t.Errorf("session mode must not be touched: %v", err)
	}
}

// The two wordings must stay one wording: CI greps the binary's output for this
// exact phrase, and so does the test above.
func TestDevAuthRefusalHasOneWording(t *testing.T) {
	cfg := &config.Config{AuthMode: "dev"}
	orig := devAuthAvailable
	devAuthAvailable = func() bool { return false }
	t.Cleanup(func() { devAuthAvailable = orig })

	viaConfig := validateDevAuthMode(cfg)
	viaEnv := refuseDevAuthOnReleaseBuild(func(k string) string {
		if k == "PROBECTL_AUTH_MODE" {
			return "dev"
		}
		return ""
	})
	if viaConfig == nil || viaEnv == nil {
		t.Fatal("both paths must refuse")
	}
	if viaConfig.Error() != viaEnv.Error() {
		t.Errorf("the same refusal is worded two ways:\n  config path: %v\n  env path:    %v", viaConfig, viaEnv)
	}
}
