// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

// `probectl verify-bundle <file>` verifies a signed auditor bundle OFFLINE.
//
// Offline is the whole point (P7). An auditor who has to ask the server whether
// its own export is genuine has verified nothing: the check must run on the file
// they were given, on a machine of their choosing, with no network and no
// credentials. So this command talks to nothing, and it prints what the bundle
// does NOT establish as prominently as what it does.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctlplne/probectl/internal/compliance"
)

const maxAuditorBundleBytes = 64 << 20 // a bundle is JSON; 64 MiB is generous

func cmdVerifyBundle(cfg Config, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	// AI-05: VerifyAuditorBundle proves the bundle is internally consistent with
	// the key EMBEDDED in it — a bundle re-signed with an attacker's own key
	// passes. The signer is only authenticated when the operator pins, out of
	// band, the fingerprint of the key they actually sign with. docs/guardrails.md G7-7.
	expected := fs.String("expected-fingerprint", "", "pinned signer fingerprint published by the operator out of band (sha256:...)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 || strings.TrimSpace(rest[0]) == "" {
		fmt.Fprintln(stderr, "usage: probectl verify-bundle [--expected-fingerprint sha256:...] <probectl-auditor-bundle.json>")
		return 2
	}
	f, err := os.Open(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "verify-bundle: %v\n", err)
		return 1
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxAuditorBundleBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "verify-bundle: read: %v\n", err)
		return 1
	}
	if len(raw) > maxAuditorBundleBytes {
		fmt.Fprintf(stderr, "verify-bundle: file larger than %d bytes\n", maxAuditorBundleBytes)
		return 1
	}
	m, err := compliance.VerifyAuditorBundle(raw)
	if err != nil {
		// A failed verification is the finding, so it is loud and it is an error
		// exit — a script must not be able to treat it as a pass.
		fmt.Fprintf(stderr, "verify-bundle: NOT VERIFIED: %v\n", err)
		return 1
	}
	// VerifyAuditorBundle already proved the bundle parses; re-read the signer
	// fingerprint so it can be pinned and shown.
	var pkg compliance.AuditorPackage
	_ = json.Unmarshal(raw, &pkg)
	signer := pkg.Signing.Fingerprint
	authenticated := false
	if *expected != "" {
		if !strings.EqualFold(strings.TrimSpace(*expected), strings.TrimSpace(signer)) {
			fmt.Fprintf(stderr, "verify-bundle: NOT VERIFIED: signer fingerprint %s does not match expected %s\n", signer, *expected)
			return 1
		}
		authenticated = true
	}
	if cfg.JSON {
		code := 0
		if !authenticated {
			code = 3
		}
		_ = printJSON(stdout, map[string]any{
			"authenticated": authenticated,
			"signer":        signer,
			"verdict":       map[bool]string{true: "verified", false: "integrity-only"}[authenticated],
			"manifest":      m,
		})
		return code
	}
	verdict := "INTEGRITY-ONLY"
	if authenticated {
		verdict = "VERIFIED"
	}
	fmt.Fprintf(stdout, "%s  %s\n", verdict, m.Contract)
	fmt.Fprintf(stdout, "  signer          %s\n", signer)
	fmt.Fprintf(stdout, "  bundle          %s\n", m.BundleID)
	fmt.Fprintf(stdout, "  generated       %s\n", m.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(stdout, "  tenant scope    %s\n", m.TenantScopeDigest)
	fmt.Fprintf(stdout, "  built from      %s (%s)%s\n", m.Deployment.Version, m.Deployment.Commit,
		fipsSuffix(m.Deployment.FIPSMode))
	fmt.Fprintln(stdout, "  sections")
	for _, s := range m.Sections {
		line := fmt.Sprintf("    %-26s %s", s.Kind, strings.ToUpper(s.Status))
		if s.Reason != "" {
			line += " — " + s.Reason
		}
		fmt.Fprintln(stdout, line)
	}
	fmt.Fprintln(stdout, "  read this before relying on it")
	for _, c := range m.Caveats {
		fmt.Fprintln(stdout, "    - "+c)
	}
	if !authenticated {
		fmt.Fprintln(stdout, "  SIGNER NOT AUTHENTICATED — re-run with --expected-fingerprint <sha256:...> "+
			"(published by the operator out of band) to prove who signed this bundle")
		return 3
	}
	return 0
}

func fipsSuffix(on bool) string {
	if on {
		return ", FIPS module active"
	}
	return ""
}
