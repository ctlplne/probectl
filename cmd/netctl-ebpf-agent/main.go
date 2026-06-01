// Command netctl-ebpf-agent is the netctl eBPF host agent (Linux): zero-
// instrumentation L3/L4 flow capture + a live service map, emitted to the bus as
// netctl.ebpf.flows (S20). It is observe-only and never loads policy-enforcing
// programs (CLAUDE.md §7 guardrail 8).
//
// The CO-RE eBPF loader is compiled in only with `-tags ebpf` on Linux (it needs
// clang at build time and a BTF kernel + CAP_BPF at run time). Every other build
// — the default build, macOS, CI — runs from a recorded fixture
// (NETCTL_EBPF_FIXTURE_PATH / fixture_path), which is also the no-kernel test
// path. See docs/ebpf-agent.md and docs/ebpf-feasibility.md (S19a).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/ebpf"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("netctl-ebpf-agent", version.Get())
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "netctl-ebpf-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("netctl-ebpf-agent", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("NETCTL_EBPF_CONFIG"), "path to the eBPF agent YAML config")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	cfg, err := ebpf.Load(*configPath)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("NETCTL_EBPF_LOG_LEVEL", "info"), envOr("NETCTL_EBPF_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	b, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers)
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()

	agent, err := ebpf.New(cfg, b, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.Run(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
