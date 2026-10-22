// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ctlplne/probectl/internal/crypto"
)

// runTestSync is `probectl-control testsync public-key [-key-file <path>]`
// (G9, D-41): print the PEM public half of the test-bundle signing key, for
// operators who provision agents by hand (or mount it through Helm values)
// instead of through `probectl-agent enroll`, which writes it automatically.
// It reads only the key file — no database, no network — and never creates
// one: printing the public half of a key that does not exist yet would hand
// agents a key no control plane signs with.
func runTestSync(args []string, getenv func(string) string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "public-key" {
		return fmt.Errorf("usage: probectl-control testsync public-key [-key-file <path>]")
	}
	fs := flag.NewFlagSet("testsync public-key", flag.ContinueOnError)
	fs.SetOutput(stdout)
	keyFile := fs.String("key-file", getenv("PROBECTL_TESTSYNC_SIGNING_KEY_FILE"),
		"test-bundle signing key (defaults to PROBECTL_TESTSYNC_SIGNING_KEY_FILE)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *keyFile == "" {
		return fmt.Errorf("testsync public-key: no key file (set PROBECTL_TESTSYNC_SIGNING_KEY_FILE or -key-file)")
	}
	privPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("testsync public-key: %w (the control plane generates the key on first boot)", err)
	}
	pubPEM, err := crypto.PublicPEMFromPrivate(privPEM)
	if err != nil {
		return fmt.Errorf("testsync public-key: %w", err)
	}
	_, err = stdout.Write(pubPEM)
	return err
}
