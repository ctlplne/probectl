// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl-control is the probectl control-plane API server.
//
// Subcommands:
//
//	probectl-control [serve]              run the stateless HTTP API server (default)
//	probectl-control migrate              apply database migrations and exit
//	probectl-control gen-cert             write a self-signed TLS cert (HTTPS quickstart)
//	probectl-control agent-ca             init/export the agent-enrollment CA
//	probectl-control enroll-token         mint a one-time agent join token
//	probectl-control revoke-enroll-token  void an unredeemed join token early
//	probectl-control register-collector   register a bus-publishing collector (eBPF/flow/device)
//	probectl-control revoke-agent         revoke an enrolled agent's identity
//	probectl-control mcp-stdio            serve MCP over stdio (local AI clients)
//	probectl-control mcp-token            mint an MCP access token
//	probectl-control scim-token           mint a SCIM provisioning token
//	probectl-control support-bundle       write a redacted diagnostics bundle
//	probectl-control backup-seal          encrypt a backup container
//	probectl-control backup-open          decrypt a backup container for restore
//	probectl-control backup-rewrap        re-encrypt a backup container under the active KEK
//	probectl-control envelope-rewrap      rewrap live deployment-envelope secrets
//	probectl-control preflight            validate config/connectivity and exit
//	probectl-control version              print build metadata and exit
//
// Configuration is read from PROBECTL_-prefixed environment variables
// (see docs/configuration.md).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/threat"
	"github.com/imfeelingtheagi/probectl/internal/version"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if err := run(cmd); err != nil {
		// Last-resort CLI error reporting (the structured logger may not exist
		// yet, e.g. on a config-load failure).
		fmt.Fprintln(os.Stderr, "probectl-control:", err)
		os.Exit(1)
	}
}

func run(cmd string) error {
	// CODE-001: the no-DB subcommands (version/gen-cert/support-bundle/preflight/
	// backup-*) dispatch first; serve + the configured-path subcommands fall
	// through to the wiring below. Behavior is identical — this is mechanical
	// extraction of the leading dispatch switch off run()'s spine.
	if handled, err := dispatchEarlyCommand(cmd); handled {
		return err
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// S41/SEC-002/S-T6: resolve secret-reference config and install the at-rest
	// envelope sealer (extracted to setupSecretsAndEnvelope — CODE-005).
	secretsResolver, envelopeGenerated, err := setupSecretsAndEnvelope(cfg)
	if err != nil {
		return err
	}
	// mcp-stdio uses stdout for its JSON-RPC channel, so its logs go to stderr.
	logOut := os.Stdout
	if cmd == "mcp-stdio" {
		logOut = os.Stderr
	}
	log := logging.New(logOut, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)
	if envelopeGenerated {
		log.Warn("GENERATED a new at-rest envelope key — back this file up like any key material; losing it makes sealed values unreadable",
			"key_file", cfg.EnvelopeKeyFile, "key_id", cfg.EnvelopeKeyID)
	}

	if err := validateDevAuthMode(cfg); err != nil {
		return err
	}

	// FIPS power-on self-test (S-EE1): exercise every crypto primitive (KATs)
	// before serving traffic and — in the FIPS artifact — assert the validated
	// module is active. Fail closed: a control plane whose crypto self-test
	// fails must not run (guardrail 3).
	if err := crypto.PowerOnSelfTest(); err != nil {
		return fmt.Errorf("crypto power-on self-test: %w", err)
	}
	if st := crypto.Status(); st.BuildTag || st.ModuleActive {
		log.Info("crypto self-test passed",
			"fips_build", st.BuildTag, "fips_module_active", st.ModuleActive,
			"fips_enforced", st.Enforced, "module_version", st.ModuleVersion)
	}

	db, err := store.Open(context.Background(), cfg.DatabaseURL,
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.DatabaseConnTimeout)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	// Multi-region (S-EE2): an optional local read replica for read locality.
	// Empty PROBECTL_DATABASE_READ_URL = reads stay on the writer.
	if err := db.WithReadReplica(context.Background(), cfg.DatabaseReadURL,
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.DatabaseConnTimeout); err != nil {
		return err
	}

	// CODE-001: the DB-backed one-shot subcommands (migrate, mcp-*, agent-ca,
	// *-token, revoke-*, register-collector, replay-deadletter) dispatch here,
	// after the DB is open (so `defer db.Close()` above still fires). `serve`
	// falls through to the long wiring path below. Pure mechanical extraction.
	if handled, err := dispatchDBCommand(cmd, cfg, db, log); handled {
		return err
	}

	if err := verifyServePosture(context.Background(), cfg, db, log); err != nil {
		return err
	}

	log.Info("starting probectl-control", "version", version.Get().Version, "config", cfg)

	// Bus + per-plane stores (result bus, TSDB, ingest-batching writer, path,
	// otel, flow, ebpf) with their DB-level tenant reader scoping. Extracted to
	// buildServeStores (CODE-001): it returns the bundle plus ONE aggregate
	// closer that retires the long defer chain and closes everything on an early
	// error too.
	st, closeStores, err := buildServeStores(cfg, log)
	if err != nil {
		return err
	}
	defer closeStores()
	return runServe(cfg, db, log, st, secretsResolver)
}

// (WIRE-005: the bespoke loadServerTLS is gone — every probectl listener
// takes crypto.ServerTLSConfig, the ONE hardened policy: TLS 1.3 floor.)

func runMigrations(ctx context.Context, db *store.DB, log *slog.Logger) error {
	applied, err := migrate.New(migrations.FS, log).Apply(ctx, db.Pool())
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if len(applied) == 0 {
		log.Info("database schema already up to date")
	} else {
		log.Info("migrations applied", "count", len(applied), "versions", applied)
	}
	return nil
}

// intelSourceOrNil adapts the optional IOC store to the engine's seam: a nil
// *IOCStore must become a nil INTERFACE (not a typed-nil) so the engine's
// nil checks behave.
func intelSourceOrNil(s *opendata.IOCStore) threat.IntelSource {
	if s == nil {
		return nil
	}
	return s
}

// loopbackOnly reports whether addr binds exclusively to a loopback
// interface. An empty host (":8080") or a wildcard (0.0.0.0 / ::) binds every
// interface and is NOT loopback — dev auth refuses it (RED-001).
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
