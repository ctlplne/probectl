// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Command probectl-endpoint is the probectl endpoint / Digital-Experience-Monitoring
// (DEM) agent (S37, F16/F46): a lightweight, cross-OS (Linux/macOS/Windows)
// binary that runs on a user's device and captures last-mile experience — WiFi
// link health, the local gateway, the ISP/last-mile path, and browser-session
// timings — then ATTRIBUTES a slowdown to the user's WiFi, their LAN, their ISP,
// or the wider network. Enrolled endpoints send results over the operator's
// tenant-bound mTLS control connection. Direct-bus deployments keep the
// registry-verified collector path described in threat model B9.
//
//	probectl-endpoint -config /etc/probectl/endpoint.yml
//	probectl-endpoint version
//
// Privacy: it discloses exactly what it collects at startup and, by default,
// keeps only measurements — no geolocatable AP MAC, no public last-mile IPs.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/version"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-endpoint:", err)
		os.Exit(1)
	}
}

func dispatch(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "version", "-version", "--version":
			if len(args) == 2 && args[1] == "--executable-identity" {
				identity, err := crypto.RunningCodeIdentity()
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(os.Stdout, identity)
				return err
			}
			fmt.Println("probectl-endpoint", version.Get())
			return nil
		case "enroll":
			return runEndpointEnroll(args[1:], os.Stdin, os.Stdout)
		case "stage-update":
			return stageEndpointUpdate(args[1:], os.Stdout)
		}
	}
	return run(args)
}

func run(args []string) error {
	fs := flag.NewFlagSet("probectl-endpoint", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_ENDPOINT_CONFIG"), "path to the endpoint agent YAML config")
	managed := fs.Bool("managed", false, "read the current user's probectl/endpoint.yaml under the OS configuration directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *managed {
		path, err := managedEndpointConfigPath()
		if err != nil {
			return err
		}
		*configPath = path
	}

	cfg, err := endpoint.Load(*configPath)
	if *managed && errors.Is(err, os.ErrNotExist) {
		return nil // the management system may deploy configuration after the package
	}
	if err != nil {
		return err
	}
	if *managed && cfg.Control.Address == "" {
		return errors.New("managed endpoint configuration requires enrolled control transport")
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_ENDPOINT_LOG_LEVEL", "info"), envOr("PROBECTL_ENDPOINT_LOG_FORMAT", "json"))
	slog.SetDefault(log)

	if err := crypto.RunPowerOnSelfTest(log); err != nil {
		return err
	}
	enrolled := cfg.Control.Address != ""
	metricsConfig, err := endpointMetricsConfig(enrolled)
	if err != nil {
		return err
	}
	var metricsRuntime *agentmetrics.Runtime
	if metricsConfig.Addr != "" {
		build := version.Get()
		metricsRuntime, err = agentmetrics.New("probectl-endpoint", build.Version, build.Commit, metricsConfig)
		if err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if enrolled {
		return runEnrolled(ctx, cfg, metricsRuntime, log)
	}

	rawBus, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers, bus.SecurityFromEnv(os.Getenv, "PROBECTL_ENDPOINT_BUS"))
	if err != nil {
		return err
	}
	// ING-19: this is a standalone collector — nothing consumes the bus in this
	// process. Memory mode would silently drop every batch, so warn loudly.
	bus.WarnIfInProcess(log, "probectl-endpoint", cfg.Bus.Mode)
	b := agentmetrics.ObserveBus(rawBus, metricsRuntime)
	defer func() { _ = b.Close() }()

	rt, err := endpoint.New(cfg, b, log)
	if err != nil {
		return err
	}

	return metricsRuntime.RunTogether(ctx, rt.Run)
}

func managedEndpointConfigPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve managed endpoint configuration: %w", err)
	}
	return filepath.Join(base, "probectl", "endpoint.yaml"), nil
}

func endpointMetricsConfig(enrolled bool) (agentmetrics.Config, error) {
	defaultAddr := ""
	if !enrolled {
		defaultAddr = agentmetrics.DefaultEndpointAddr
	}
	cfg := agentmetrics.ConfigFromEnv(os.Getenv, "PROBECTL_ENDPOINT", defaultAddr)
	if !enrolled || cfg == (agentmetrics.Config{}) {
		return cfg, nil
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return agentmetrics.Config{}, errors.New("enrolled endpoint metrics require both a TLS certificate and key")
	}
	if cfg.Addr == "" {
		// Per-user launchers can run at the same time on one device.
		cfg.Addr = "127.0.0.1:0"
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
