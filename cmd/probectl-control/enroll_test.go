// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
func TestAgentCAInitIfMissingIsTheRepeatableForm(t *testing.T) {
	src, err := os.ReadFile("enroll.go")
	if err != nil {
		t.Fatalf("read enroll.go: %v", err)
	}
	s := string(src)
	start := strings.Index(s, "func runAgentCAInit")
	if start < 0 {
		t.Fatal("runAgentCAInit not found")
	}
	body := s[start:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end]
	}
	if !strings.Contains(body, `fs.Bool("if-missing"`) {
		t.Error("agent-ca init must offer -if-missing for automated bootstraps")
	}
	// The check must happen BEFORE any key material is generated, or a repeat
	// run would mint a root key it then throws away.
	initIdx := strings.Index(body, "enroll.CAInitialized")
	genIdx := strings.Index(body, "enroll.InitCA")
	if initIdx < 0 || genIdx < 0 || initIdx > genIdx {
		t.Error("-if-missing must short-circuit before InitCA generates key material")
	}
	// And the refusal must stay the DEFAULT: silence on an existing CA is opt-in.
	if !strings.Contains(body, "*ifMissing") {
		t.Error("the no-op must be gated on the flag, not unconditional")
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
func TestAgentCARenewRefusalNamesTheFormThatWorksInAContainer(t *testing.T) {
	src, err := os.ReadFile("enroll.go")
	if err != nil {
		t.Fatalf("read enroll.go: %v", err)
	}
	s := string(src)
	start := strings.Index(s, "func runAgentCARenew")
	if start < 0 {
		t.Fatal("runAgentCARenew not found")
	}
	body := s[start:]
	if end := strings.Index(body[1:], "\nfunc "); end > 0 {
		body = body[:end]
	}
	for _, want := range []string{"exec -i", "-root-key -", "no shell and no tar"} {
		if !strings.Contains(body, want) {
			t.Errorf("the missing-flag refusal must mention %q: an operator on the shipped image has no other way in", want)
		}
	}
}
