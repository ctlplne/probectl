// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command probectl-device-agent is the probectl device-telemetry collector
// (S39, F18): an SNMP poller (v2c/v3 — IF-MIB interface health + HC counters,
// HOST-RESOURCES CPU/memory, optional entity temperature sensors) and a
// gNMI/OpenConfig streaming subscriber, both normalized into DeviceMetric and
// published to the bus as probectl.device.metrics. The control plane consumes
// the topic and lands the samples in the TSDB; SNMP polls also build the
// interface inventory that correlates path hops and flow records onto devices.
//
// Credentials are referenced by NAME and resolved through the CredentialSource
// seam: the PROBECTL_DEVICE_CRED_<NAME>_* environment layout, where each field
// value may be a SECRET REFERENCE (S41 — env:/vault:/cyberark:/aws:/azure:/gcp:)
// resolved through the secret backends configured in the environment, with
// short-lived leases and per-poll re-resolution. Plain values pass through as
// literals. Secrets are never logged. See docs/secrets.md and
// docs/device-telemetry.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	agentmetrics "github.com/imfeelingtheagi/probectl/internal/agent/metrics"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/device"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/secrets"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-device-agent", version.Get())
			return
		case "discover":
			if err := runDiscover(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "probectl-device-agent discover:", err)
				os.Exit(1)
			}
			return
		case "config-check":
			if err := runConfigCheck(os.Args[2:], os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "probectl-device-agent config-check:", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-device-agent:", err)
		os.Exit(1)
	}
}

// runConfigCheck expands the effective collection plan without constructing a
// secret resolver, bus, runtime, or network client. Its JSON is therefore safe
// to attach to a review ticket before agent startup.
func runConfigCheck(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("probectl-device-agent config-check", flag.ContinueOnError)
	configPath := fs.String("config", os.Getenv("PROBECTL_DEVICE_CONFIG"), "path to the device collector YAML config")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	cfg, err := device.Load(*configPath)
	if err != nil {
		return err
	}
	preview, err := cfg.EffectiveCollectionPreview()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(preview)
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

	if err := crypto.RunPowerOnSelfTest(log); err != nil {
		return err
	}
	build := version.Get()
	metricsRuntime, err := agentmetrics.New("probectl-device-agent", build.Version, build.Commit,
		agentmetrics.ConfigFromEnv(os.Getenv, "PROBECTL_DEVICE", agentmetrics.DefaultDeviceAddr))
	if err != nil {
		return err
	}

	rawBus, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers, bus.SecurityFromEnv(os.Getenv, "PROBECTL_DEVICE_BUS"))
	if err != nil {
		return err
	}
	b := agentmetrics.ObserveBus(rawBus, metricsRuntime)
	defer func() { _ = b.Close() }()

	// S41: device credentials resolve through the secret backends configured in
	// the environment. Plain env values keep working (literal passthrough); a
	// misconfigured backend fails closed at startup.
	res, err := secrets.FromEnv(0)
	if err != nil {
		return err
	}
	defer res.Close()
	creds, err := device.NewSecretsCredentials(nil, res.Resolve)
	if err != nil {
		return err
	}
	log.Info("secret backends configured", "schemes", res.Schemes())

	emitter, eerr := device.NewNamespacedBusEmitter(b, cfg.TenantID, cfg.Bus.Namespace)
	if eerr != nil {
		return eerr // RED-006: malformed silo namespace refuses start
	}
	rt, err := device.New(cfg, emitter, creds, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return metricsRuntime.RunTogether(ctx, rt.Run)
}

func runDiscover(args []string) error {
	fs := flag.NewFlagSet("probectl-device-agent discover", flag.ContinueOnError)
	jobPath := fs.String("job", "", "path to JSON discovery job")
	fixturePath := fs.String("fixture", "", "optional JSON fixture for offline discovery")
	outPath := fs.String("out", "-", "output path for review JSON (- for stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *jobPath == "" {
		return fmt.Errorf("-job is required")
	}
	jobFile, err := os.Open(*jobPath)
	if err != nil {
		return fmt.Errorf("read job: %w", err)
	}
	defer jobFile.Close()
	var job device.DiscoveryJob
	dec := json.NewDecoder(jobFile)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		return fmt.Errorf("parse job: %w", err)
	}

	res, err := secrets.FromEnv(0)
	if err != nil {
		return err
	}
	defer res.Close()
	creds, err := device.NewSecretsCredentials(nil, res.Resolve)
	if err != nil {
		return err
	}
	var prober device.DiscoveryProber = device.SNMPDiscoveryProber{}
	if *fixturePath != "" {
		fixtureFile, err := os.Open(*fixturePath)
		if err != nil {
			return fmt.Errorf("read fixture: %w", err)
		}
		defer fixtureFile.Close()
		prober, err = device.LoadDiscoveryFixture(fixtureFile)
		if err != nil {
			return fmt.Errorf("parse fixture: %w", err)
		}
	}
	result, err := device.RunDiscovery(context.Background(), job, creds, prober, time.Now)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if *outPath == "-" {
		_, err = os.Stdout.Write(raw)
		return err
	}
	return os.WriteFile(*outPath, raw, 0o600)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
