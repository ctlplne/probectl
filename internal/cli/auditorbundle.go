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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctlplne/probectl/internal/compliance"
)

const maxAuditorBundleBytes = 64 << 20 // a bundle is JSON; 64 MiB is generous

func cmdVerifyBundle(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.TrimSpace(args[0]) == "" {
		fmt.Fprintln(stderr, "usage: probectl verify-bundle <probectl-auditor-bundle.json>")
		return 2
	}
	f, err := os.Open(args[0])
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
	if cfg.JSON {
		return printJSON(stdout, m)
	}
	fmt.Fprintf(stdout, "VERIFIED  %s\n", m.Contract)
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
	return 0
}

func fipsSuffix(on bool) string {
	if on {
		return ", FIPS module active"
	}
	return ""
}
