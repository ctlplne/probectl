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
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/flow"
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

	collector, err := flow.New(cfg, flow.NewBusEmitter(b, cfg.TenantID), log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return collector.Run(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
