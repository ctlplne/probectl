// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package preflight

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckIDP(t *testing.T) {
	if f := CheckIDP("dev", ""); f.Severity != Warn || !strings.Contains(f.Detail, "dev") {
		t.Fatalf("dev auth mode must warn: %+v", f)
	}
	// RTO-05: session auth with no OIDC issuer is local-bootstrap-only — a Warn
	// that trips --strict, where the shipped check used to be silent.
	if f := CheckIDP("session", ""); f.Severity != Warn || !strings.Contains(f.Detail, "no external IdP") {
		t.Fatalf("session auth with no IdP must warn: %+v", f)
	}
	if f := CheckIDP("session", "https://idp.example/realms/ops"); f.Severity != OK {
		t.Fatalf("configured OIDC issuer must be OK: %+v", f)
	}
}

func TestCheckEnvelopeKeyFile(t *testing.T) {
	// PLAT-15: a configured-but-missing key file reported OK before this check.
	if f := CheckEnvelopeKeyFile(filepath.Join(t.TempDir(), "absent.key")); f.Severity != Warn || !strings.Contains(f.Detail, "not readable") {
		t.Fatalf("missing key file must warn: %+v", f)
	}

	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(empty, []byte("\n\n  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := CheckEnvelopeKeyFile(empty); f.Severity != Warn || !strings.Contains(f.Detail, "empty") {
		t.Fatalf("empty key file must warn: %+v", f)
	}

	if f := CheckEnvelopeKeyFile(dir); f.Severity != Warn || !strings.Contains(f.Detail, "directory") {
		t.Fatalf("a directory must warn: %+v", f)
	}

	good := filepath.Join(dir, "kek.key")
	if err := os.WriteFile(good, []byte("c29tZS1iYXNlNjQta2V5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if f := CheckEnvelopeKeyFile(good); f.Severity != OK {
		t.Fatalf("a present readable key file must be OK: %+v", f)
	}
}

func TestCheckDatastoreReachable(t *testing.T) {
	// A listening endpoint is reachable.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	okDial := func(network, addr string, _ time.Duration) (net.Conn, error) {
		return net.Dial(network, addr)
	}
	if f := CheckDatastoreReachable("postgres", ln.Addr().String(), okDial, time.Second); f.Severity != OK {
		t.Fatalf("a listening endpoint must be reachable: %+v", f)
	}

	// PLAT-15: an unreachable datastore must warn (trips --strict).
	failDial := func(_, _ string, _ time.Duration) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	if f := CheckDatastoreReachable("postgres", "127.0.0.1:1", failDial, time.Second); f.Severity != Warn || !strings.Contains(f.Detail, "not reachable") {
		t.Fatalf("an unreachable datastore must warn: %+v", f)
	}

	// No endpoint configured is an informational skip, not a Warn.
	if f := CheckDatastoreReachable("postgres", "", failDial, time.Second); f.Severity != Info {
		t.Fatalf("no endpoint must be an info skip: %+v", f)
	}
}

func TestClassifyDBPrivilege(t *testing.T) {
	// RTO-05 / G7-1: a superuser or BYPASSRLS login defeats FORCE RLS.
	if f := ClassifyDBPrivilege(true, false); f.Severity != Warn || !strings.Contains(f.Detail, "SUPERUSER") {
		t.Fatalf("superuser must warn: %+v", f)
	}
	if f := ClassifyDBPrivilege(false, true); f.Severity != Warn || !strings.Contains(f.Detail, "BYPASSRLS") {
		t.Fatalf("BYPASSRLS must warn: %+v", f)
	}
	if f := ClassifyDBPrivilege(false, false); f.Severity != OK {
		t.Fatalf("least-privilege role must be OK: %+v", f)
	}
}
