// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"os"
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
