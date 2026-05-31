// Command netctl-control is the netctl control-plane API server.
//
// Subcommands:
//
//	netctl-control [serve]   run the stateless HTTP API server (default)
//	netctl-control migrate   apply database migrations and exit
//	netctl-control version   print build metadata and exit
//
// Configuration is read from NETCTL_-prefixed environment variables
// (see docs/configuration.md).
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/imfeelingtheagi/netctl/internal/a2a"
	"github.com/imfeelingtheagi/netctl/internal/agenttransport"
	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/control"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/pipeline"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/migrate"
	"github.com/imfeelingtheagi/netctl/internal/store/tsdb"
	"github.com/imfeelingtheagi/netctl/internal/version"
	"github.com/imfeelingtheagi/netctl/migrations"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if err := run(cmd); err != nil {
		// Last-resort CLI error reporting (the structured logger may not exist
		// yet, e.g. on a config-load failure).
		fmt.Fprintln(os.Stderr, "netctl-control:", err)
		os.Exit(1)
	}
}

func run(cmd string) error {
	switch cmd {
	case "version", "-version", "--version":
		fmt.Println("netctl-control", version.Get())
		return nil
	case "serve", "migrate":
		// fall through to the configured path below
	default:
		return fmt.Errorf("unknown command %q (want: serve | migrate | version)", cmd)
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := logging.New(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	db, err := store.Open(context.Background(), cfg.DatabaseURL,
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.DatabaseConnTimeout)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	if cmd == "migrate" {
		return runMigrations(context.Background(), db, log)
	}

	if cfg.MigrateOnBoot {
		if err := runMigrations(context.Background(), db, log); err != nil {
			return err
		}
	}

	log.Info("starting netctl-control", "version", version.Get().Version, "config", cfg)

	// Result pipeline: a message bus that the control plane consumes and writes
	// to the TSDB. The bus is shared with the agent transport (the publisher).
	resultBus, err := bus.New(cfg.BusMode, cfg.BusBrokers)
	if err != nil {
		return fmt.Errorf("result bus: %w", err)
	}
	defer resultBus.Close()
	tsdbWriter, err := tsdb.New(cfg.TSDBMode, cfg.TSDBURL)
	if err != nil {
		return fmt.Errorf("tsdb: %w", err)
	}
	defer tsdbWriter.Close()

	// Brokers agent-to-agent measurement sessions; sessions are started by the
	// test API in a later sprint.
	a2aBroker := a2a.NewBroker()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the HTTP API, the result-pipeline consumer, and (when configured) the
	// agent gRPC transport together; a signal or a failure in any drains all.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return control.New(cfg, log, db, db.Pool()).Run(gctx) })
	g.Go(func() error { return pipeline.NewConsumer(resultBus, tsdbWriter, pipeline.DefaultGroup, log).Run(gctx) })
	if cfg.AgentTransportEnabled() {
		grpcSrv, err := agenttransport.New(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile, cfg.AgentTLSCAFile, db.Pool(), resultBus, a2aBroker, log)
		if err != nil {
			return fmt.Errorf("agent transport: %w", err)
		}
		g.Go(func() error { return grpcSrv.Serve(gctx, cfg.AgentGRPCAddr) })
	}
	return g.Wait()
}

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
