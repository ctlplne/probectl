// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl-flow-agent is the probectl passive flow collector (S38,
// F17): NetFlow v5/v9, IPFIX, and sFlow v5 listeners that decode exporter
// datagrams (templates, sampling correction) into normalized, tenant-bound
// records and publish batches to the bus as probectl.flow.events. The control
// plane consumes the topic, enriches ASN/geo (S15), and persists to ClickHouse
// for top-talkers / capacity / anomaly analytics.
//
// Flow export protocols are plaintext UDP by design, so the collector treats
// every datagram as untrusted (bounds-checked decoders, capped template state)
// and should be deployed adjacent to the exporters on a management network.
// See docs/flow.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/flow"
	"github.com/imfeelingtheagi/probectl/internal/flow/cloudflow"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-flow-agent", version.Get())
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-flow-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("probectl-flow-agent", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_FLOW_CONFIG"), "path to the flow collector YAML config")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	cfg, err := flow.Load(*configPath)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_FLOW_LOG_LEVEL", "info"), envOr("PROBECTL_FLOW_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	b, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers, bus.SecurityFromEnv(os.Getenv, "PROBECTL_FLOW_BUS"))
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()

	emitter, err := flow.NewNamespacedBusEmitter(b, cfg.TenantID, cfg.Bus.Namespace)
	if err != nil {
		return err // RED-006: malformed silo namespace refuses start
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cfg.CloudImport.Provider != "" {
		return runCloudImport(ctx, cfg, emitter, log)
	}

	collector, err := flow.New(cfg, emitter, log)
	if err != nil {
		return err
	}
	return collector.Run(ctx)
}

func runCloudImport(ctx context.Context, cfg *flow.Config, emitter flow.Emitter, log *slog.Logger) error {
	var r io.Reader = os.Stdin
	if cfg.CloudImport.Path != "-" {
		f, err := os.Open(cfg.CloudImport.Path)
		if err != nil {
			return fmt.Errorf("flow: open cloud import file: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	n, err := cloudflow.Emit(ctx, cloudflow.Provider(cfg.CloudImport.Provider), cfg.TenantID, cfg.AgentID, r, emitter)
	if err != nil {
		return err
	}
	log.Info("flow: cloud import complete",
		"provider", cfg.CloudImport.Provider,
		"path", cfg.CloudImport.Path,
		"records", n,
		"tenant", cfg.TenantID)
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
