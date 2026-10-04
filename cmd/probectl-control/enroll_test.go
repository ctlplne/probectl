// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/enroll"
)

// TestAgentCAInitRefusesToLogTheRootKey (DPR-121): "shown once, never stored"
// was true of the database and depended entirely on how the command ran.
// Through kubectl exec the key reaches the operator's terminal; through a Job,
// a Helm hook or a CI step — the ordinary way to automate a bootstrap — the
// same bytes land in the cluster's log store with nothing said about it. A
// root CA private key in a log is what guardrail 6 forbids.
func TestAgentCAInitRefusesToLogTheRootKey(t *testing.T) {
	// A pipe is what a Job's stdout is: not a character device.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if isTerminal(w) {
		t.Fatal("a pipe must not be treated as a terminal")
	}
	// The database is never reached: the refusal happens before the CA is
	// generated, so a refused run leaves nothing half-created.
	err = runAgentCAInit(context.Background(), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to print the root CA private key") {
		t.Fatalf("a non-terminal stdout must be refused, got %v", err)
	}
	if !strings.Contains(err.Error(), "-key-out") || !strings.Contains(err.Error(), "-print-key") {
		t.Errorf("the refusal must name both safe paths: %v", err)
	}
}

// DPR-136: `agent-ca init` refusing to overwrite the trust root is correct, and
// it made every bootstrap one-shot single-use — a second `compose up`, a
// re-applied Job or a re-run pipeline step failed on a deployment that was
// already correct and took everything downstream with it. -if-missing is the
// repeatable form, and it must never overwrite.
func TestAgentCAInitIfMissingIsANoOpOnAnInitializedCA(t *testing.T) {
	ctx := context.Background()
	db := setupBootstrapAdminDB(t)

	// Ensure an initialized CA (idempotent setup: tolerate a CA a prior test in
	// this shared DB already minted). -key-out satisfies the non-terminal-stdout
	// guard — go test stdout is not a TTY — so a fresh init actually creates one.
	if err := runAgentCAInit(ctx, db, []string{"-key-out", filepath.Join(t.TempDir(), "root.key")}); err != nil &&
		!strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("first init: %v", err)
	}
	before, err := enroll.PublicBundle(ctx, db.Pool())
	if err != nil {
		t.Fatalf("bundle before: %v", err)
	}

	// -if-missing on an already-initialized CA must succeed and change nothing.
	// A broken variant fails here: dropping the flag -> unknown-flag parse error;
	// dropping the no-op branch -> the non-terminal-stdout refusal; reordering so
	// InitCA runs before the CAInitialized short-circuit -> InitCA's
	// "already initialized (refusing to overwrite the trust root)" error.
	if err := runAgentCAInit(ctx, db, []string{"-if-missing"}); err != nil {
		t.Fatalf("-if-missing on an initialized CA must be a no-op, got: %v", err)
	}

	after, err := enroll.PublicBundle(ctx, db.Pool())
	if err != nil {
		t.Fatalf("bundle after: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("-if-missing regenerated the trust root; it must leave an existing CA untouched")
	}
}

// DPR-191: `agent-ca renew` is the only way out of a one-year agent-CA expiry,
// and as first written it could not be run on the image the chart ships. It took
// the root key as a FILE inside the container, and that container is distroless:
// `kubectl cp` into it fails with `exec: "tar": executable file not found in
// $PATH` because there is no tar and no shell. The workaround an operator would
// reach for — mounting the root key as a Secret — writes the offline root into
// etcd and onto every replica, which is the one thing keeping it offline exists
// to prevent. "-" now means stdin, matching `agent-ca export -`.
func TestReadRootKeyAcceptsStdinSoRenewalWorksOnADistrolessImage(t *testing.T) {
	const pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"

	t.Run("dash reads stdin verbatim", func(t *testing.T) {
		got, err := readRootKey("-", strings.NewReader(pem))
		if err != nil {
			t.Fatalf("stdin must be accepted: %v", err)
		}
		if string(got) != pem {
			t.Errorf("stdin bytes must reach the caller unchanged, got %q", got)
		}
	})

	t.Run("a file still works", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "root.key")
		if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := readRootKey(path, nil)
		if err != nil {
			t.Fatalf("the file form must keep working: %v", err)
		}
		if string(got) != pem {
			t.Errorf("file bytes must reach the caller unchanged, got %q", got)
		}
	})

	t.Run("empty stdin is named, not treated as a key", func(t *testing.T) {
		_, err := readRootKey("-", strings.NewReader(""))
		if err == nil {
			t.Fatal("empty stdin must not be handed on as a key")
		}
		// `kubectl exec` without -i gives the command a closed stdin, which is
		// the mistake this message exists to shortcut.
		if !strings.Contains(err.Error(), "exec -i") {
			t.Errorf("the error must name the likely cause: %v", err)
		}
	})

	t.Run("stdin is bounded", func(t *testing.T) {
		_, err := readRootKey("-", strings.NewReader(strings.Repeat("x", maxRootKeyBytes+1)))
		if err == nil || !strings.Contains(err.Error(), "not a private key PEM") {
			t.Fatalf("an unbounded read is how a pipe becomes a memory fault, got %v", err)
		}
	})

	t.Run("a missing file says so", func(t *testing.T) {
		_, err := readRootKey(filepath.Join(t.TempDir(), "absent.key"), nil)
		if err == nil || !strings.Contains(err.Error(), "read root key") {
			t.Fatalf("a missing file must be reported as one, got %v", err)
		}
	})
}

// And the refusal an operator hits when they forget the flag entirely has to
// tell them the form that works inside the container, because the obvious one
// (`kubectl cp` the key in) cannot work there at all.
func TestAgentCARenewRefusalNamesTheContainerSafeForm(t *testing.T) {
	// No -root-key: the refusal returns before any DB access, so a nil db is safe.
	// Asserting on the returned error VALUE (not source text) survives a reformat
	// of the message and fails if the container-safe guidance is dropped, or if
	// the required-flag guard is removed (control then reaches readRootKey("")
	// and errors without naming "exec -i").
	err := runAgentCARenew(context.Background(), nil, nil, nil)
	if err == nil {
		t.Fatal("agent-ca renew must refuse when -root-key is omitted")
	}
	for _, want := range []string{"exec -i", "-root-key -", "no shell and no tar"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the missing-flag refusal must name the container-safe form %q: %v", want, err)
		}
	}
}
