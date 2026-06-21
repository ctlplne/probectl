// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl-ebpf-agent is the probectl eBPF host agent (Linux): zero-
// instrumentation L3/L4 flow capture + a live service map, emitted to the bus as
// probectl.ebpf.flows (S20). It is observe-only and never loads policy-enforcing
// programs (CLAUDE.md §7 guardrail 8).
//
// The CO-RE eBPF loader is compiled in only with `-tags ebpf` on Linux (it needs
// clang at build time and a BTF kernel + CAP_BPF at run time). Every other build
// — the default build, macOS, CI — runs from a recorded fixture
// (PROBECTL_EBPF_FIXTURE_PATH / fixture_path), which is also the no-kernel test
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

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/ebpf"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-ebpf-agent", version.Get())
			return
		case "healthcheck":
			if err := runHealthcheck(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "probectl-ebpf-agent healthcheck:", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-ebpf-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("probectl-ebpf-agent", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_EBPF_CONFIG"), "path to the eBPF agent YAML config")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	cfg, err := ebpf.Load(*configPath)
	if err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_EBPF_LOG_LEVEL", "info"), envOr("PROBECTL_EBPF_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	b, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers, bus.SecurityFromEnv(os.Getenv, "PROBECTL_EBPF_BUS"))
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

	// OPS-001: serve liveness/readiness probes for the DaemonSet when
	// configured. Runs alongside the agent; a probe failure surfaces a stuck
	// attach to Kubernetes instead of a silently-dead pod.
	if cfg.HealthAddr != "" {
		health := ebpf.NewHealthServer(cfg.HealthAddr, agent)
		go func() {
			if herr := health.Run(ctx); herr != nil {
				log.Error("ebpf health server stopped", "error", herr.Error())
			}
		}()
	}
	if err := ebpf.StartHealthFileWriter(ctx, cfg.HealthStateDir, agent); err != nil {
		return err
	}
	return agent.Run(ctx)
}

func runHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	stateDir := fs.String("state-dir", ebpf.DefaultHealthStateDir, "directory containing eBPF agent health state files")
	live := fs.Bool("live", false, "check liveness")
	ready := fs.Bool("ready", false, "check readiness")
	maxAge := fs.Duration("max-age", ebpf.DefaultHealthStateMaxAge, "maximum accepted state file age")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *live == *ready {
		return fmt.Errorf("set exactly one of --live or --ready")
	}
	name := "live"
	if *ready {
		name = "ready"
	}
	return ebpf.CheckHealthState(*stateDir, name, *maxAge)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
