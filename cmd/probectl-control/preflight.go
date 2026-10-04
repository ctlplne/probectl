// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/preflight"
	"github.com/ctlplne/probectl/internal/store"
)

// runPreflight is the operator deployment self-check (Sprint 8 —
// SEC-002/COMPLY-004): probectl's own at-rest sealing posture, the operator's
// storage-encryption duties for the bulk telemetry volumes (docs/hardening.md),
// and the production-readiness posture the original check never looked at —
// database privilege (G7-1), IdP, a usable envelope key file, datastore
// reachability (RTO-05/PLAT-15). Warnings exit 0 by default; --strict exits 1
// so regulated profiles and CI can gate on it.
//
//	probectl-control preflight [--strict] [--paths /var/lib/postgresql,/var/lib/clickhouse]
func runPreflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	strictFlag := fs.Bool("strict", false, "exit non-zero on warnings (regulated profiles, CI)")
	paths := fs.String("paths", "/var/lib/probectl",
		"comma-separated data paths whose backing mounts are checked for at-rest encryption")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	findings := gatherPreflightFindings(cfg, *paths, defaultPreflightDeps())

	worst := 0
	for _, f := range findings {
		fmt.Printf("[%-4s] %-40s %s\n", strings.ToUpper(string(f.Severity)), f.Check, f.Detail)
		if f.Severity == preflight.Warn {
			worst = 1
		}
	}
	if *strictFlag && worst != 0 {
		return fmt.Errorf("preflight: warnings present and --strict set (operator duties: docs/hardening.md)")
	}
	return nil
}

// preflightDeps are the live-environment probes the finding-gatherer needs,
// injectable so gatherPreflightFindings is deterministic in unit tests.
type preflightDeps struct {
	dial         preflight.DialFunc
	dbPrivilege  func(ctx context.Context, dsn string) (superuser, bypassRLS bool, err error)
	readMounts   func() (string, error)
	dialTimeout  time.Duration
	queryTimeout time.Duration
}

// defaultPreflightDeps wires the real net dialer, the live pg_roles privilege
// query, and /proc/self/mounts.
func defaultPreflightDeps() preflightDeps {
	return preflightDeps{
		dial:         net.DialTimeout,
		dbPrivilege:  liveDBPrivilege,
		readMounts:   preflight.ReadSelfMounts,
		dialTimeout:  3 * time.Second,
		queryTimeout: 3 * time.Second,
	}
}

// liveDBPrivilege connects briefly and asks Postgres whether the control
// plane's own role is a superuser or carries BYPASSRLS (RTO-05, G7-1).
func liveDBPrivilege(ctx context.Context, dsn string) (bool, bool, error) {
	db, err := store.Open(ctx, dsn, 1, 0, 3*time.Second)
	if err != nil {
		return false, false, err
	}
	defer db.Close()
	var superuser, bypassRLS bool
	row := db.Pool().QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`)
	if err := row.Scan(&superuser, &bypassRLS); err != nil {
		return false, false, err
	}
	return superuser, bypassRLS, nil
}

// gatherPreflightFindings runs every posture check. It is pure w.r.t. its
// injected deps so the full CLI finding set is unit-testable without a live
// database or network.
func gatherPreflightFindings(cfg *config.Config, paths string, deps preflightDeps) []preflight.Finding {
	var findings []preflight.Finding

	keyConfigured := cfg.EnvelopeKey != "" || cfg.EnvelopeKeyFile != ""
	findings = append(findings, preflight.CheckEnvelopeKey(keyConfigured, cfg.RequireAtRestEncryption, cfg.AllowKeylessDev))
	// PLAT-15: a configured key FILE that is missing/empty/unreadable is a trap —
	// CheckEnvelopeKey only saw that a path was set, not that it is usable.
	if cfg.EnvelopeKey == "" && cfg.EnvelopeKeyFile != "" {
		findings = append(findings, preflight.CheckEnvelopeKeyFile(cfg.EnvelopeKeyFile))
	}

	// PLAT-01/RTO-04: memory-backed telemetry planes without an explicit ack.
	findings = append(findings, preflight.CheckVolatileStores(cfg.VolatileStores(), cfg.VolatileAcknowledged()))

	// RTO-05: IdP posture (no SSO → local bootstrap auth only).
	findings = append(findings, preflight.CheckIDP(cfg.AuthMode, cfg.OIDCIssuer))

	// PLAT-15: datastore reachability, then RTO-05: database privilege (G7-1).
	if addr := hostPortFromDSN(cfg.DatabaseURL); addr != "" {
		reach := preflight.CheckDatastoreReachable("postgres", addr, deps.dial, deps.dialTimeout)
		findings = append(findings, reach)
		if reach.Severity != preflight.Warn && deps.dbPrivilege != nil {
			ctx, cancel := context.WithTimeout(context.Background(), deps.queryTimeout)
			superuser, bypassRLS, err := deps.dbPrivilege(ctx, cfg.DatabaseURL)
			cancel()
			if err != nil {
				findings = append(findings, preflight.Finding{Check: "db-privilege", Severity: preflight.Warn,
					Detail: fmt.Sprintf("cannot determine the control plane's database privilege (%v) — verify it is a least-privilege, non-superuser, non-BYPASSRLS role (G7-1)", err)})
			} else {
				findings = append(findings, preflight.ClassifyDBPrivilege(superuser, bypassRLS))
			}
		}
	}

	// Storage-encryption duty for the bulk telemetry volumes.
	attested := strings.EqualFold(os.Getenv("PROBECTL_STORAGE_ENCRYPTION_ATTESTED"), "true")
	mounts, merr := deps.readMounts()
	if merr != nil {
		findings = append(findings, preflight.Finding{
			Check: "storage-encryption", Severity: preflight.Warn,
			Detail: fmt.Sprintf("cannot read /proc/self/mounts (%v) — assess volume encryption manually (docs/hardening.md)", merr)})
	} else {
		var ps []string
		for _, p := range strings.Split(paths, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ps = append(ps, p)
			}
		}
		findings = append(findings, preflight.CheckStorageEncryption(mounts, ps, attested)...)
	}
	return findings
}

// hostPortFromDSN extracts host:port from a postgres:// DSN for the
// reachability probe; "" when the DSN is empty or unparseable (no probe).
func hostPortFromDSN(dsn string) string {
	if strings.TrimSpace(dsn) == "" {
		return ""
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		return ""
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	return net.JoinHostPort(host, port)
}
