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
