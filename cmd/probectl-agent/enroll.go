// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/version"
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
	fmt.Println("agent config snippet:")
	fmt.Printf("  tls:\n    cert_file: %s/%s\n    key_file: %s/%s\n    ca_file: %s/%s\n",
		*dir, agent.IdentityCertFile, *dir, agent.IdentityKeyFile, *dir, agent.IdentityCAFile)
	fmt.Printf("  identity:\n    server: %s\n", *server)
	return nil
}
