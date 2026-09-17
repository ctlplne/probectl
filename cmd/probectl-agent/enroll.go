// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/version"
)

// runEnroll is the first-contact bootstrap (Sprint 11):
//
//	probectl-agent enroll --server https://control:8443 --token pjt_... \
//	    --dir /var/lib/probectl-agent/identity [--ca-pin <hex sha256>|--ca-file ca.crt]
//
// It generates the key locally (never leaves the host), redeems the one-time
// token for a tenant-bound SVID, writes key/cert/bundle (0600), and prints the
// config snippet. The server derives the tenant from the TOKEN.
func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	server := fs.String("server", "", "control-plane base URL (https://host:8443)")
	token := fs.String("token", "", "one-time enrollment token (pjt_..., shown when minted)")
	dir := fs.String("dir", "/var/lib/probectl-agent/identity", "identity directory (key/cert/bundle)")
	caPin := fs.String("ca-pin", "", "hex sha256 of the server certificate (printed at token mint; first-contact trust for self-signed deployments)")
	caFile := fs.String("ca-file", "", "CA bundle to verify the server against (CA-issued certs)")
	hostname := fs.String("hostname", "", "agent hostname (defaults to os.Hostname)")
	allowPlaintextLoopback := fs.Bool("allow-plaintext-loopback", false, "dev/test only: allow http://localhost or loopback enrollment")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	spiffeID, notAfter, err := agent.Enroll(ctx, agent.EnrollOptions{
		Server: *server, Token: *token, Dir: *dir,
		Hostname: *hostname, Version: version.Get().Version,
		CAPin: *caPin, CAFile: *caFile,
		AllowPlaintextLoopback: *allowPlaintextLoopback,
	})
	if err != nil {
		return err
	}
	fmt.Println("enrolled:", spiffeID)
	fmt.Println("svid expires:", notAfter.UTC().Format(time.RFC3339), "(auto-rotates at ~2/3 lifetime when identity.server is set)")
	fmt.Println()
	// DPR-021: tls.ca_file verifies the CONTROL PLANE (its gRPC listener
	// presents the API's server certificate), so it must be the trust used to
	// reach the server — persisted as server-ca.pem from --ca-file / --ca-pin —
	// never the agent-CA bundle (ca.pem), which only vouches for agents.
	serverCA := filepath.Join(*dir, agent.IdentityServerCAFile)
	if _, err := os.Stat(serverCA); err != nil {
		// Enrolled against the system roots (no --ca-file / --ca-pin): the
		// runtime must verify the server with the same trust.
		serverCA = "/etc/ssl/certs/ca-certificates.crt   # the system bundle (enrolled against system roots)"
	}
	fmt.Println("agent config snippet:")
	fmt.Printf("  tls:\n    cert_file: %s/%s\n    key_file: %s/%s\n    ca_file: %s\n",
		*dir, agent.IdentityCertFile, *dir, agent.IdentityKeyFile, serverCA)
	fmt.Printf("  identity:\n    server: %s\n", *server)
	return nil
}

// runRotate forces one proof-of-possession SVID rotation through the public
// agent binary. The private key remains local: agent.Rotate signs the new CSR
// with the current key and atomically replaces the identity files only after
// the HTTPS response verifies against the enrolled CA bundle.
func runRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ContinueOnError)
	server := fs.String("server", "", "control-plane HTTPS base URL")
	dir := fs.String("dir", "/var/lib/probectl-agent/identity", "identity directory")
	caFile := fs.String("ca-file", "", "CA bundle for the control-plane HTTPS certificate (defaults to <dir>/server-ca.pem written at enrollment, else <dir>/ca.pem)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *server == "" || *dir == "" {
		return fmt.Errorf("--server and --dir are required")
	}
	if err := crypto.RunPowerOnSelfTest(nil); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	notAfter, err := agent.Rotate(
		ctx,
		*server,
		filepath.Join(*dir, agent.IdentityCertFile),
		filepath.Join(*dir, agent.IdentityKeyFile),
		rotationTrustFile(*dir, *caFile),
	)
	if err != nil {
		return err
	}
	fmt.Println("rotated identity in:", *dir)
	fmt.Println("svid expires:", notAfter.UTC().Format(time.RFC3339))
	return nil
}

// rotationTrustFile picks the bundle that verifies the control plane's HTTPS
// certificate during a rotation: an explicit --ca-file wins; otherwise the
// server trust enrollment captured (server-ca.pem, DPR-021); otherwise the
// agent-CA bundle, for deployments whose server certificates are issued by the
// agent CA itself.
func rotationTrustFile(dir, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if p := filepath.Join(dir, agent.IdentityServerCAFile); fileExists(p) {
		return p
	}
	return filepath.Join(dir, agent.IdentityCAFile)
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
