// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

// runTestSync is `probectl-control testsync public-key [-key-file <path>]`
// (G9, D-41): print the PEM public half of the test-bundle signing key, for
// operators who provision agents by hand (or mount it through Helm values)
// instead of through `probectl-agent enroll`, which writes it automatically.
// The key is the one the serving process uses: an explicit -key-file, else the
// inline PROBECTL_TESTSYNC_SIGNING_KEY (Helm and other secret-injected HA
// deployments), else PROBECTL_TESTSYNC_SIGNING_KEY_FILE. It reads only that key
// — no database, no network — and never creates one: printing the public half
// of a key that does not exist yet would hand agents a key no control plane
// signs with.
func runTestSync(args []string, getenv func(string) string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "public-key" {
		return fmt.Errorf("usage: probectl-control testsync public-key [-key-file <path>]")
	}
	fs := flag.NewFlagSet("testsync public-key", flag.ContinueOnError)
	fs.SetOutput(stdout)
	keyFile := fs.String("key-file", "",
		"test-bundle signing key file (default: PROBECTL_TESTSYNC_SIGNING_KEY, else PROBECTL_TESTSYNC_SIGNING_KEY_FILE)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	privPEM, err := testSyncPrivateKey(*keyFile, getenv)
	if err != nil {
		return fmt.Errorf("testsync public-key: %w", err)
	}
	pubPEM, err := crypto.PublicPEMFromPrivate(privPEM)
	if err != nil {
		return fmt.Errorf("testsync public-key: %w", err)
	}
	_, err = stdout.Write(pubPEM)
	return err
}

func testSyncPrivateKey(explicitFile string, getenv func(string) string) ([]byte, error) {
	if explicitFile == "" {
		if inline := strings.TrimSpace(getenv("PROBECTL_TESTSYNC_SIGNING_KEY")); inline != "" {
			priv, err := base64.StdEncoding.DecodeString(inline)
			if err != nil {
				return nil, fmt.Errorf("PROBECTL_TESTSYNC_SIGNING_KEY is not valid base64: %w", err)
			}
			return priv, nil
		}
		explicitFile = getenv("PROBECTL_TESTSYNC_SIGNING_KEY_FILE")
	}
	if explicitFile == "" {
		return nil, fmt.Errorf("no key configured (set PROBECTL_TESTSYNC_SIGNING_KEY or PROBECTL_TESTSYNC_SIGNING_KEY_FILE, or pass -key-file)")
	}
	priv, err := os.ReadFile(explicitFile)
	if err != nil {
		return nil, fmt.Errorf("%w (the control plane generates the key file on first boot)", err)
	}
	return priv, nil
}
