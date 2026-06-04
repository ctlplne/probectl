// Command probectl-endpoint is the probectl endpoint / Digital-Experience-Monitoring
// (DEM) agent (S37, F16/F46): a lightweight, cross-OS (Linux/macOS/Windows)
// binary that runs on a user's device and captures last-mile experience — WiFi
// link health, the local gateway, the ISP/last-mile path, and browser-session
// timings — then ATTRIBUTES a slowdown to the user's WiFi, their LAN, their ISP,
// or the wider network. It emits like every other agent (results to the
// operator's own bus, tenant-tagged); it never phones home.
//
//	probectl-endpoint -config /etc/probectl/endpoint.yml
//	probectl-endpoint version
//
// Privacy: it discloses exactly what it collects at startup and, by default,
// keeps only measurements — no geolocatable AP MAC, no public last-mile IPs.
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
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-endpoint", version.Get())
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-endpoint:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("probectl-endpoint", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_ENDPOINT_CONFIG"), "path to the endpoint agent YAML config")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	cfg, err := endpoint.Load(*configPath)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_ENDPOINT_LOG_LEVEL", "info"), envOr("PROBECTL_ENDPOINT_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	b, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers)
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()

	rt, err := endpoint.New(cfg, b, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return rt.Run(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
