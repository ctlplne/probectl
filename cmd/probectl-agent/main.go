// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"path/filepath"
	"syscall"

	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-agent", version.Get())
			return
		case "enroll":
			// Sprint 11 (ADR docs/adr/agent-enrollment.md): redeem a one-time
			// join token for a tenant-bound SVID and write the identity dir.
			if err := runEnroll(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "probectl-agent enroll:", err)
				os.Exit(1)
			}
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

	// FIPS power-on self-test (S-EE1): the agent's mTLS/identity crypto is the
	// same abstraction; fail closed if the self-test fails (guardrail 3).
	if err := crypto.PowerOnSelfTest(); err != nil {
		return fmt.Errorf("crypto power-on self-test: %w", err)
	}
	if st := crypto.Status(); st.BuildTag || st.ModuleActive {
		log.Info("crypto self-test passed", "fips_build", st.BuildTag,
			"fips_module_active", st.ModuleActive, "module_version", st.ModuleVersion)
	}

	// Signal context first, so SIGTERM cancels a first-boot enrollment retry.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// First-boot enrollment (optional, RED-002): with no identity yet and a
	// one-time join token available (PROBECTL_AGENT_JOIN_TOKEN or
	// enroll.token_file), enroll before starting — idempotent and fail-closed.
	joinToken, err := cfg.JoinToken()
	if err != nil {
		return err
	}
	enrollServer := cfg.Enroll.Server
	if enrollServer == "" {
		enrollServer = cfg.Identity.Server
	}
	if err := agent.EnsureIdentity(ctx, agent.EnrollOptions{
		Server:                 enrollServer,
		Token:                  joinToken,
		Dir:                    filepath.Dir(cfg.TLS.CertFile),
		Hostname:               cfg.Agent.Hostname,
		Version:                version.Get().Version,
		CAFile:                 cfg.TLS.CAFile,
		CAPin:                  cfg.Enroll.CAPin,
		AllowPlaintextLoopback: cfg.Enroll.AllowPlaintextLoopback,
	}, log); err != nil {
		return err
	}

	// RED-008: constrain probe ca_file parameters to the allowlisted dir
	// ("" = the parameter is refused — fail closed).
	canary.SetCAFileDir(cfg.TLS.CanaryCADir)

	// Compiled-in canary plugins.
	reg := canary.NewRegistry()
	reg.Register("noop", canary.NewNoop)
	reg.Register("icmp", canary.NewICMP)
	reg.Register("tcp", canary.NewTCP)
	reg.Register("udp", canary.NewUDP)
	reg.Register("dns", canary.NewDNS)
	reg.Register("http", canary.NewHTTP)
	reg.Register("voice", canary.NewVoice) // RTP MOS/jitter/loss (S47c)

	a, err := agent.New(cfg, reg, log)
	if err != nil {
		return err
	}

	// Automatic SVID rotation (Sprint 11): rotate the on-disk identity at
	// ~2/3 of its lifetime; the mTLS client hot-reloads the swap.
	if cfg.Identity.Server != "" && (cfg.Identity.AutoRotate == nil || *cfg.Identity.AutoRotate) {
		go agent.RotationLoop(ctx, log, cfg.Identity.Server,
			cfg.TLS.CertFile, cfg.TLS.KeyFile, cfg.TLS.CAFile, 0)
		log.Info("automatic SVID rotation enabled", "server", cfg.Identity.Server)
	}
	return a.Run(ctx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
