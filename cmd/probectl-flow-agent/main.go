// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/ctlplne/probectl/internal/agent"
	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/flow/cloudflow"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/version"
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

	if err := crypto.RunPowerOnSelfTest(log); err != nil {
		return err
	}
	build := version.Get()
	metricsRuntime, err := agentmetrics.New("probectl-flow-agent", build.Version, build.Commit,
		agentmetrics.ConfigFromEnv(os.Getenv, "PROBECTL_FLOW", agentmetrics.DefaultFlowAddr))
	if err != nil {
		return err
	}

	rawBus, err := bus.New(cfg.Bus.Mode, cfg.Bus.Brokers, bus.SecurityFromEnv(os.Getenv, "PROBECTL_FLOW_BUS"))
	if err != nil {
		return err
	}
	// ING-19: this is a standalone collector — nothing consumes the bus in this
	// process. Memory mode would silently drop every batch, so warn loudly.
	bus.WarnIfInProcess(log, "probectl-flow-agent", cfg.Bus.Mode)
	b := agentmetrics.ObserveBus(rawBus, metricsRuntime)
	defer func() { _ = b.Close() }()

	emitter, err := flow.NewNamespacedBusEmitter(b, cfg.TenantID, cfg.Bus.Namespace)
	if err != nil {
		return err // RED-006: malformed silo namespace refuses start
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if cfg.CloudImport.Provider != "" {
		return metricsRuntime.RunTogether(ctx, func(ctx context.Context) error {
			return runCloudImport(ctx, cfg, emitter, log)
		})
	}

	collector, err := flow.New(cfg, emitter, log)
	if err != nil {
		return err
	}
	var evidenceClient *agent.EvidenceClient
	if cfg.Evidence.Enabled() {
		if err := agent.ValidateEvidenceRotation(cfg.Evidence.RotateURL,
			cfg.Evidence.CertFile, cfg.Evidence.KeyFile, cfg.Evidence.CAFile); err != nil {
			return fmt.Errorf("flow evidence renewal: %w", err)
		}
		client, err := agent.DialEntityEvidence(cfg.Evidence.ControlAddr,
			cfg.Evidence.CertFile, cfg.Evidence.KeyFile, cfg.Evidence.CAFile,
			cfg.Evidence.ServerName)
		if err != nil {
			return fmt.Errorf("flow evidence identity: %w", err)
		}
		defer client.Close()
		evidenceClient = client
		tenantID, agentID := client.Identity()
		if tenantID != cfg.TenantID || agentID != cfg.AgentID {
			return fmt.Errorf("flow evidence certificate does not match configured tenant and agent")
		}
		collector.WithEntityEvidence(observedFlowEvidence{client: client, metrics: metricsRuntime})
		go agent.RotationLoopOnSuccess(ctx, log, cfg.Evidence.RotateURL,
			cfg.Evidence.CertFile, cfg.Evidence.KeyFile, cfg.Evidence.CAFile, 0,
			func() {
				if err := evidenceClient.ReconnectAfterRotation(); err != nil {
					log.Warn("flow evidence connection renewal failed", "error", err.Error())
				}
				collector.RefreshEvidenceAfterRotation()
			})
	}
	return metricsRuntime.RunTogether(ctx, collector.Run)
}

type observedFlowEvidence struct {
	client  *agent.EvidenceClient
	metrics *agentmetrics.Runtime
}

func (o observedFlowEvidence) Submit(ctx context.Context, observations []entity.Observation) (int, int, error) {
	accepted, unresolved, err := o.client.Submit(ctx, observations)
	o.metrics.EntityEvidence(accepted, unresolved, err)
	return accepted, unresolved, err
}

func (o observedFlowEvidence) SubmitFaults(ctx context.Context, faults []entity.FaultObservation) (int, error) {
	accepted, err := o.client.SubmitFaults(ctx, faults)
	o.metrics.EntityFault(err)
	return accepted, err
}

func (o observedFlowEvidence) QueueDrop() { o.metrics.EntityEvidenceQueueDrop() }

func runCloudImport(ctx context.Context, cfg *flow.Config, emitter flow.Emitter, log *slog.Logger) error {
	var r io.Reader = os.Stdin
	if cfg.CloudImport.Path != "-" {
		f, err := os.Open(cfg.CloudImport.Path)
		if err != nil {
			return fmt.Errorf("flow: open cloud import file: %w", err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	n, malformed, err := cloudflow.Emit(ctx, cloudflow.Provider(cfg.CloudImport.Provider), cfg.TenantID, cfg.AgentID, r, emitter)
	if err != nil {
		return err
	}
	// RTP-20: malformed lines are skipped, not fatal; report how many so an
	// operator sees that a partial export still imported its valid records.
	log.Info("flow: cloud import complete",
		"provider", cfg.CloudImport.Provider,
		"path", cfg.CloudImport.Path,
		"records", n,
		"malformed", malformed,
		"tenant", cfg.TenantID)
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
