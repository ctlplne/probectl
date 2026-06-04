// Command probectl-agent is the probectl canary agent — a single, statically linked,
// multi-arch binary with compiled-in canary plugins, a disk-backed
// store-and-forward buffer, and a tenant-bound mTLS connection to the control
// plane.
//
//	probectl-agent -config /etc/probectl/agent.yml
//	probectl-agent version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-agent", version.Get())
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("probectl-agent", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_AGENT_CONFIG"), "path to the agent YAML config")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *configPath == "" {
		return fmt.Errorf("a config file is required (-config or PROBECTL_AGENT_CONFIG)")
	}

	cfg, err := agent.Load(*configPath)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_AGENT_LOG_LEVEL", "info"), envOr("PROBECTL_AGENT_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	// Compiled-in canary plugins.
	reg := canary.NewRegistry()
	reg.Register("noop", canary.NewNoop)
	reg.Register("icmp", canary.NewICMP)
	reg.Register("tcp", canary.NewTCP)
	reg.Register("udp", canary.NewUDP)
	reg.Register("dns", canary.NewDNS)
	reg.Register("http", canary.NewHTTP)

	a, err := agent.New(cfg, reg, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
