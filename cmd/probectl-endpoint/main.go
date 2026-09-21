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

	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/version"
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

	if err := crypto.RunPowerOnSelfTest(log); err != nil {
		return err
	}
	build := version.Get()
	metricsRuntime, err := agentmetrics.New("probectl-endpoint", build.Version, build.Commit,
		agentmetrics.ConfigFromEnv(os.Getenv, "PROBECTL_ENDPOINT", agentmetrics.DefaultEndpointAddr))
	if err != nil {
		return err
	}

	rawBus, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers, bus.SecurityFromEnv(os.Getenv, "PROBECTL_ENDPOINT_BUS"))
	if err != nil {
		return err
	}
	b := agentmetrics.ObserveBus(rawBus, metricsRuntime)
	defer func() { _ = b.Close() }()

	rt, err := endpoint.New(cfg, b, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return metricsRuntime.RunTogether(ctx, rt.Run)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
