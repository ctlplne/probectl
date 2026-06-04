// Command probectl-device-agent is the probectl device-telemetry collector
// (S39, F18): an SNMP poller (v2c/v3 — IF-MIB interface health + HC counters,
// HOST-RESOURCES CPU/memory, optional entity temperature sensors) and a
// gNMI/OpenConfig streaming subscriber, both normalized into DeviceMetric and
// published to the bus as probectl.device.metrics. The control plane consumes
// the topic and lands the samples in the TSDB; SNMP polls also build the
// interface inventory that correlates path hops and flow records onto devices.
//
// Credentials are referenced by NAME and resolved through the CredentialSource
// seam — the environment provider (PROBECTL_DEVICE_CRED_<NAME>_*) is the
// pre-S41 default; S41 plugs Vault/CyberArk into the same seam. Secrets are
// never logged. See docs/device-telemetry.md.
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
	"github.com/imfeelingtheagi/probectl/internal/device"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-device-agent", version.Get())
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-device-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("probectl-device-agent", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_DEVICE_CONFIG"), "path to the device collector YAML config")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	cfg, err := device.Load(*configPath)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_DEVICE_LOG_LEVEL", "info"), envOr("PROBECTL_DEVICE_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	b, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers)
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()

	rt, err := device.New(cfg, device.NewBusEmitter(b, cfg.TenantID), nil, log)
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
