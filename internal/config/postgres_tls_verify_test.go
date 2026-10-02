// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
)

// TestPostgresTLSRequiresServerVerificationForTenantProfiles pins CRY-05: under
// the production-like (multi-tenant/regulated) deployment profiles a PostgreSQL
// DSN must actually verify the server certificate. sslmode=require encrypts but
// trusts any certificate the peer presents, so it must fail closed exactly like
// prefer/allow/disable; only sslmode=verify-ca or verify-full WITH an
// sslrootcert trust anchor is accepted (docs/guardrails.md G7-12). Single/dev
// profiles keep today's behavior and still accept sslmode=require.
//
// It drives the real config loader (config.Load) so the baseline (pre-fix)
// compiles and fails on behavior, not on a missing symbol.
func TestPostgresTLSRequiresServerVerificationForTenantProfiles(t *testing.T) {
	const (
		secureWriterDSN = "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=verify-full&sslrootcert=/run/secrets/pg-ca.pem"
		requireOnlyDSN  = "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=require"
	)

	tenantCases := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{
			name:    "require-only is rejected (no server verification)",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=require",
			wantErr: true,
		},
		{
			name:    "prefer is rejected",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=prefer",
			wantErr: true,
		},
		{
			name:    "allow is rejected",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=allow",
			wantErr: true,
		},
		{
			name:    "disable is rejected",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=disable",
			wantErr: true,
		},
		{
			name:    "verify-ca without sslrootcert is rejected",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=verify-ca",
			wantErr: true,
		},
		{
			name:    "verify-full without sslrootcert is rejected",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=verify-full",
			wantErr: true,
		},
		{
			name:    "verify-ca with sslrootcert is accepted",
			dsn:     "postgres://probectl:test-only@pg.example:5432/probectl?sslmode=verify-ca&sslrootcert=/run/secrets/pg-ca.pem",
			wantErr: false,
		},
		{
			name:    "verify-full with sslrootcert is accepted",
			dsn:     secureWriterDSN,
			wantErr: false,
		},
	}

	for _, profile := range []string{"multi-tenant", "regulated"} {
		for _, tc := range tenantCases {
			t.Run(profile+"/"+tc.name, func(t *testing.T) {
				env := durableTenantProfileEnv(profile)
				env["PROBECTL_DATABASE_URL"] = tc.dsn
				_, err := Load(envFunc(env))
				if tc.wantErr {
					if err == nil {
						t.Fatalf("profile %s DSN %q was accepted; want fail-closed server-verification refusal", profile, tc.dsn)
					}
					if !strings.Contains(err.Error(), "PROBECTL_DATABASE_URL") || !strings.Contains(err.Error(), "sslrootcert") {
						t.Fatalf("profile %s DSN %q error = %v; want it to name PROBECTL_DATABASE_URL and sslrootcert guidance", profile, tc.dsn, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("profile %s DSN %q should load (verify-* with sslrootcert): %v", profile, tc.dsn, err)
				}
			})
		}

		t.Run(profile+"/require read replica is rejected", func(t *testing.T) {
			env := durableTenantProfileEnv(profile)
			env["PROBECTL_DATABASE_URL"] = secureWriterDSN
			env["PROBECTL_DATABASE_READ_URL"] = requireOnlyDSN
			_, err := Load(envFunc(env))
			if err == nil || !strings.Contains(err.Error(), "PROBECTL_DATABASE_READ_URL") || !strings.Contains(err.Error(), "sslrootcert") {
				t.Fatalf("profile %s require-only read replica should fail closed with server-verification guidance, got %v", profile, err)
			}
		})
	}

	// Single/dev profile keeps today's behavior: sslmode=require still loads.
	t.Run("single profile still accepts require", func(t *testing.T) {
		cfg, err := Load(envFunc(map[string]string{
			"PROBECTL_DEPLOYMENT_PROFILE": "single",
			"PROBECTL_DATABASE_URL":       requireOnlyDSN,
		}))
		if err != nil {
			t.Fatalf("single profile sslmode=require should remain loadable: %v", err)
		}
		if cfg.DatabaseURL != requireOnlyDSN {
			t.Fatalf("single profile DatabaseURL = %q, want %q", cfg.DatabaseURL, requireOnlyDSN)
		}
	})
}
