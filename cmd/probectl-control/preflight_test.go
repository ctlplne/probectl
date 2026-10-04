// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/preflight"
)

// findingByCheck indexes a preflight finding set by its Check name.
func findingByCheck(fs []preflight.Finding) map[string]preflight.Severity {
	m := map[string]preflight.Severity{}
	for _, f := range fs {
		m[f.Check] = f.Severity
	}
	return m
}

// RTO-05 + PLAT-15: `preflight --strict` must FAIL a production-unsafe stack —
// a database superuser login (defeats RLS, G7-1), no external IdP, and a
// configured-but-unreadable envelope key file. The originally shipped check
// looked only at the envelope key and disk encryption and PASSED such a stack.
// This drives the real CLI gatherer with injected probes so it is deterministic
// without a live database or network.
func TestPreflightStrictFailsUnsafeStack(t *testing.T) {
	cfg := &config.Config{
		AuthMode:        "session",
		OIDCIssuer:      "", // no IdP
		EnvelopeKey:     "",
		EnvelopeKeyFile: filepath.Join(t.TempDir(), "absent.key"), // unreadable
		DatabaseURL:     "postgres://probectl:pw@db.internal:5432/probectl?sslmode=require",
	}
	deps := preflightDeps{
		// datastore reachable, so the privilege probe runs
		dial: func(_, _ string, _ time.Duration) (net.Conn, error) {
			c, _ := net.Pipe()
			return c, nil
		},
		// the control plane connects as a superuser
		dbPrivilege: func(_ context.Context, _ string) (bool, bool, error) {
			return true, false, nil
		},
		readMounts:   func() (string, error) { return "/dev/mapper/luks / ext4 rw 0 0\n", nil },
		dialTimeout:  time.Second,
		queryTimeout: time.Second,
	}

	fs := gatherPreflightFindings(cfg, "/var/lib/probectl", deps)
	got := findingByCheck(fs)

	if got["idp"] != preflight.Warn {
		t.Errorf("no-IdP must WARN (RTO-05): %v", got["idp"])
	}
	if got["envelope-key-file"] != preflight.Warn {
		t.Errorf("unreadable key file must WARN (PLAT-15): %v", got["envelope-key-file"])
	}
	if got["reachable-postgres"] != preflight.OK {
		t.Errorf("reachable postgres must be OK here: %v", got["reachable-postgres"])
	}
	if got["db-privilege"] != preflight.Warn {
		t.Errorf("superuser DB login must WARN (RTO-05/G7-1): %v", got["db-privilege"])
	}

	// The whole point: --strict exits non-zero on this stack.
	worst := preflight.Severity("")
	for _, f := range fs {
		if f.Severity == preflight.Warn {
			worst = preflight.Warn
		}
	}
	if worst != preflight.Warn {
		t.Fatalf("preflight --strict must fail on a superuser/no-IdP/unreadable-key stack; findings=%+v", fs)
	}
}

// PLAT-15: an unreachable datastore must WARN and skip the (impossible)
// privilege probe rather than silently passing.
func TestPreflightUnreachableDatastoreWarns(t *testing.T) {
	cfg := &config.Config{
		AuthMode:    "session",
		OIDCIssuer:  "https://idp.example/realms/ops",
		EnvelopeKey: "aGVsbG8=",
		DatabaseURL: "postgres://probectl:pw@db.internal:5432/probectl?sslmode=require",
	}
	privilegeCalled := false
	deps := preflightDeps{
		dial: func(_, _ string, _ time.Duration) (net.Conn, error) {
			return nil, errors.New("connection refused")
		},
		dbPrivilege: func(_ context.Context, _ string) (bool, bool, error) {
			privilegeCalled = true
			return false, false, nil
		},
		readMounts:   func() (string, error) { return "/dev/mapper/luks / ext4 rw 0 0\n", nil },
		dialTimeout:  time.Second,
		queryTimeout: time.Second,
	}

	got := findingByCheck(gatherPreflightFindings(cfg, "/var/lib/probectl", deps))
	if got["reachable-postgres"] != preflight.Warn {
		t.Errorf("unreachable postgres must WARN: %v", got["reachable-postgres"])
	}
	if privilegeCalled {
		t.Error("privilege probe must be skipped when the datastore is unreachable")
	}
}

// A hardened stack (external IdP, inline key, least-privilege reachable DB,
// encrypted disk) passes --strict.
func TestPreflightStrictPassesHardenedStack(t *testing.T) {
	cfg := &config.Config{
		AuthMode:    "session",
		OIDCIssuer:  "https://idp.example/realms/ops",
		EnvelopeKey: "aGVsbG8=",
		DatabaseURL: "postgres://probectl_runtime:pw@db.internal:5432/probectl?sslmode=verify-full",
	}
	deps := preflightDeps{
		dial: func(_, _ string, _ time.Duration) (net.Conn, error) {
			c, _ := net.Pipe()
			return c, nil
		},
		dbPrivilege:  func(_ context.Context, _ string) (bool, bool, error) { return false, false, nil },
		readMounts:   func() (string, error) { return "/dev/mapper/luks / ext4 rw 0 0\n", nil },
		dialTimeout:  time.Second,
		queryTimeout: time.Second,
	}
	for _, f := range gatherPreflightFindings(cfg, "/var/lib/probectl", deps) {
		if f.Severity == preflight.Warn {
			t.Errorf("hardened stack must not warn, got %s: %s", f.Check, f.Detail)
		}
	}
}
