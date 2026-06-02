// Command netctl-control is the netctl control-plane API server.
//
// Subcommands:
//
//	netctl-control [serve]   run the stateless HTTP API server (default)
//	netctl-control migrate   apply database migrations and exit
//	netctl-control gen-cert  write a self-signed TLS cert (HTTPS quickstart)
//	netctl-control version   print build metadata and exit
//
// Configuration is read from NETCTL_-prefixed environment variables
// (see docs/configuration.md).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/imfeelingtheagi/netctl/internal/a2a"
	"github.com/imfeelingtheagi/netctl/internal/agenttransport"
	"github.com/imfeelingtheagi/netctl/internal/alert"
	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/control"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/otel/otlp"
	"github.com/imfeelingtheagi/netctl/internal/pipeline"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/migrate"
	"github.com/imfeelingtheagi/netctl/internal/store/pathstore"
	"github.com/imfeelingtheagi/netctl/internal/store/tsdb"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
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
	case "gen-cert":
		// Self-signed TLS cert for the HTTPS-by-default quickstart; no DB needed.
		return genCert(os.Args[2:])
	case "serve", "migrate", "mcp-stdio", "mcp-token":
		// fall through to the configured path below
	default:
		return fmt.Errorf("unknown command %q (want: serve | migrate | mcp-stdio | mcp-token | gen-cert | version)", cmd)
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// mcp-stdio uses stdout for its JSON-RPC channel, so its logs go to stderr.
	logOut := os.Stdout
	if cmd == "mcp-stdio" {
		logOut = os.Stderr
	}
	log := logging.New(logOut, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	db, err := store.Open(context.Background(), cfg.DatabaseURL,
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.DatabaseConnTimeout)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	switch cmd {
	case "migrate":
		return runMigrations(context.Background(), db, log)
	case "mcp-stdio":
		return runMCPStdio(cfg, log, db)
	case "mcp-token":
		return runMCPToken(log, db, os.Args[2:])
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

	pathStore, err := pathstore.New(cfg.PathStoreMode, cfg.PathStoreURL)
	if err != nil {
		return fmt.Errorf("path store: %w", err)
	}
	defer pathStore.Close()

	// Brokers agent-to-agent measurement sessions; sessions are started by the
	// test API in a later sprint.
	a2aBroker := a2a.NewBroker()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the HTTP API, the result-pipeline consumer, and (when configured) the
	// agent gRPC transport together; a signal or a failure in any drains all.
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return control.New(cfg, log, db, db.Pool(), pathStore, nil).Run(gctx) })
	g.Go(func() error { return pipeline.NewConsumer(resultBus, tsdbWriter, pipeline.DefaultGroup, log).Run(gctx) })

	// Incident correlation (S17): related signals across planes group into one
	// incident. Alerts feed it via a sink; BGP events via a bus consumer.
	correlator := control.BuildCorrelator(db.Pool(), cfg.IncidentWindow, log)
	g.Go(func() error {
		return control.NewBGPIncidentConsumer(resultBus, correlator, log).Run(gctx)
	})

	// Threat-intel enrichment (S28): build the shared IOC store + refresher. OFF
	// unless configured (enabling it makes outbound feed fetches). The store
	// enriches BOTH the TLS/cert analyzer (malicious cert/JA3) and an IP/host
	// consumer over network results; matches are confidence-scored signals.
	iocStore, iocRefresher, intelOn := control.BuildThreatIntel(cfg, log)
	if intelOn {
		g.Go(func() error { return iocRefresher.Run(gctx) })
		g.Go(func() error {
			return control.NewIOCConsumer(resultBus, correlator, iocStore, log).Run(gctx)
		})
		log.Info("threat-intel enrichment enabled", "refresh", cfg.ThreatIntelRefresh)
	}

	// TLS/cert posture (S27): analyze captured TLS from HTTPS synthetic results
	// into threat-plane incidents (expiry/weakness + a certctl renewal handoff),
	// reusing already-captured TLS — never re-handshaking. When threat-intel is on,
	// the analyzer also scores the leaf cert SHA1 + JA3 against IOCs (S28).
	tlsAnalyzer := control.BuildTLSAnalyzer(cfg)
	if iocStore != nil {
		tlsAnalyzer.WithIntel(iocStore)
	}
	g.Go(func() error {
		return control.NewTLSPostureConsumer(resultBus, correlator, tlsAnalyzer, log).Run(gctx)
	})

	// Alerting (S16): evaluate enabled rules over the TSDB, notify channels, and
	// correlate fired alerts into incidents. Disabled gracefully when the TSDB has
	// no in-process query backend.
	if ev, ok := control.BuildAlertEvaluator(db.Pool(), tsdbWriter, alert.ChannelDeps{},
		cfg.AlertEvalInterval, tenancy.DefaultTenantID, control.AlertSink(correlator, log), log); ok {
		g.Go(func() error { ev.Run(gctx); return nil })
	} else {
		log.Info("alert evaluation disabled (no in-process TSDB query backend in this mode)")
	}
	if cfg.AgentTransportEnabled() {
		grpcSrv, err := agenttransport.New(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile, cfg.AgentTLSCAFile, db.Pool(), resultBus, a2aBroker, log)
		if err != nil {
			return fmt.Errorf("agent transport: %w", err)
		}
		g.Go(func() error { return grpcSrv.Serve(gctx, cfg.AgentGRPCAddr) })
	}

	// OTLP receiver (S22): TLS-only, authenticated, tenant-scoped ingest of
	// external OTLP. Ingested metrics are tenant-tagged and published to the bus.
	if cfg.OTLPEnabled() {
		tlsCfg, err := loadServerTLS(cfg.OTLPTLSCertFile, cfg.OTLPTLSKeyFile)
		if err != nil {
			return fmt.Errorf("otlp tls: %w", err)
		}
		sink := otlp.NewBusSink(func(ctx context.Context, tenant string, payload []byte) error {
			return resultBus.Publish(ctx, bus.OTLPMetricsTopic, []byte(tenant), payload)
		})
		otlpSrv, err := otlp.NewServer(
			otlp.ServerConfig{GRPCAddr: cfg.OTLPGRPCAddr, HTTPAddr: cfg.OTLPHTTPAddr},
			tlsCfg, otlp.NewTokenAuthenticator(cfg.OTLPTokens), sink, log)
		if err != nil {
			return fmt.Errorf("otlp receiver: %w", err)
		}
		g.Go(func() error { return otlpSrv.Run(gctx) })
	}

	// MCP server (S25): the Model Context Protocol HTTP transport — TLS + bearer-
	// authenticated, tenant- + RBAC-scoped read tools. Off unless configured.
	if cfg.MCPEnabled() {
		tlsCfg, err := loadServerTLS(cfg.MCPTLSCertFile, cfg.MCPTLSKeyFile)
		if err != nil {
			return fmt.Errorf("mcp tls: %w", err)
		}
		mcpSrv := control.NewMCPServer(cfg, log, db.Pool(), pathStore, cfg.MCPRatePerMin)
		handler := mcpSrv.HTTPHandler(control.NewMCPAuthenticator(db.Pool()))
		g.Go(func() error { return serveMCPHTTP(gctx, cfg.MCPHTTPAddr, tlsCfg, handler, log) })
	}

	return g.Wait()
}

// loadServerTLS builds a server TLS config from a cert/key pair. crypto/tls is
// permitted by the FIPS import guard; TLS policy stays centralized.
func loadServerTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
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
