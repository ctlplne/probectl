// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package preflight

import (
	"fmt"
	"net"
	"os"
	"time"
)

// This file extends the operator self-check beyond at-rest sealing (RTO-05,
// PLAT-15). The originally shipped `preflight --strict` passed a stack that is
// unsafe for production in three ways it never looked at: the control plane
// connecting as a database superuser (which bypasses the FORCE-RLS tenant
// boundary, docs/guardrails.md G7-1), no external IdP (local bootstrap auth
// only), a configured-but-unreadable envelope key FILE (sealing will fail at
// boot), and unreachable datastores. Each is now a Warn so `--strict` exits
// non-zero for regulated profiles and CI.

// CheckIDP reports the SSO/IdP posture (RTO-05). Session auth with no OIDC
// issuer configured means local bootstrap/password auth only — no federated
// SSO/MFA — which is a Warn for production. Dev auth mode is always a Warn.
func CheckIDP(authMode, oidcIssuer string) Finding {
	switch {
	case authMode == "dev":
		return Finding{Check: "idp", Severity: Warn, Detail: "PROBECTL_AUTH_MODE=dev — authentication is bypassed; never use outside local development"}
	case oidcIssuer == "":
		return Finding{Check: "idp", Severity: Warn, Detail: "no external IdP configured (PROBECTL_OIDC_ISSUER empty) — local bootstrap/password auth only, no federated SSO/MFA. Configure an OIDC IdP for production (docs/configuration.md)"}
	default:
		return Finding{Check: "idp", Severity: OK, Detail: "external OIDC IdP configured (federated SSO/MFA)"}
	}
}

// CheckEnvelopeKeyFile reports whether a configured envelope key FILE is
// actually usable (PLAT-15). CheckEnvelopeKey only sees that a path is set;
// a missing, empty, or unreadable file is a trap — the control plane counts
// the key as "configured" yet will fail to seal tenant values at boot. Only
// called when a file (not an inline env key) is the configured source.
func CheckEnvelopeKeyFile(path string) Finding {
	info, err := os.Stat(path)
	if err != nil {
		return Finding{Check: "envelope-key-file", Severity: Warn,
			Detail: fmt.Sprintf("PROBECTL_ENVELOPE_KEY_FILE=%s is configured but not readable (%v) — the control plane will FAIL to seal tenant values at boot", path, err)}
	}
	if info.IsDir() {
		return Finding{Check: "envelope-key-file", Severity: Warn,
			Detail: fmt.Sprintf("PROBECTL_ENVELOPE_KEY_FILE=%s is a directory, not a key file", path)}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Finding{Check: "envelope-key-file", Severity: Warn,
			Detail: fmt.Sprintf("PROBECTL_ENVELOPE_KEY_FILE=%s is configured but unreadable (%v)", path, err)}
	}
	if len(trimKeyFile(b)) == 0 {
		return Finding{Check: "envelope-key-file", Severity: Warn,
			Detail: fmt.Sprintf("PROBECTL_ENVELOPE_KEY_FILE=%s is empty — no key material", path)}
	}
	return Finding{Check: "envelope-key-file", Severity: OK, Detail: "envelope key file is present and readable"}
}

// trimKeyFile strips trailing whitespace/newlines a key file may carry.
func trimKeyFile(b []byte) []byte {
	for len(b) > 0 {
		switch b[len(b)-1] {
		case '\n', '\r', ' ', '\t':
			b = b[:len(b)-1]
		default:
			return b
		}
	}
	return b
}

// DialFunc dials a datastore for the reachability probe (injectable for tests).
type DialFunc func(network, address string, timeout time.Duration) (net.Conn, error)

// CheckDatastoreReachable probes TCP reachability of a datastore (PLAT-15).
// addr is a host:port; an empty addr yields an informational skip (the plane
// may be memory-backed). This is a plain reachability probe, not a data
// channel — TLS and credentials are exercised by the real pools at boot.
func CheckDatastoreReachable(name, addr string, dial DialFunc, timeout time.Duration) Finding {
	check := "reachable-" + name
	if addr == "" {
		return Finding{Check: check, Severity: Info, Detail: name + " has no network endpoint configured (memory-backed or unset)"}
	}
	conn, err := dial("tcp", addr, timeout)
	if err != nil {
		return Finding{Check: check, Severity: Warn,
			Detail: fmt.Sprintf("%s at %s is not reachable (%v) — the control plane will not boot against it", name, addr, err)}
	}
	_ = conn.Close()
	return Finding{Check: check, Severity: OK, Detail: name + " is reachable at " + addr}
}

// ClassifyDBPrivilege grades the control plane's database login (RTO-05). A
// superuser or BYPASSRLS role defeats the FORCE-RLS tenant boundary that is
// probectl's outermost isolation guarantee (docs/guardrails.md G7-1): RLS
// policies simply do not apply to such a login, so one tenant's query can read
// another tenant's rows. The control plane must connect as a least-privilege,
// RLS-subject role.
func ClassifyDBPrivilege(superuser, bypassRLS bool) Finding {
	switch {
	case superuser:
		return Finding{Check: "db-privilege", Severity: Warn,
			Detail: "the control plane connects as a database SUPERUSER — superusers bypass row-level security, defeating tenant isolation (docs/guardrails.md G7-1). Create a least-privilege, non-superuser, non-BYPASSRLS role (docs/install.md)"}
	case bypassRLS:
		return Finding{Check: "db-privilege", Severity: Warn,
			Detail: "the control plane's database role has BYPASSRLS — it is not subject to the FORCE-RLS tenant boundary (docs/guardrails.md G7-1). Use a role without BYPASSRLS"}
	default:
		return Finding{Check: "db-privilege", Severity: OK, Detail: "database role is least-privilege (RLS-subject, no superuser/BYPASSRLS)"}
	}
}
