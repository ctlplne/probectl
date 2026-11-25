// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/ctlplne/probectl/internal/agent"
	agentmetrics "github.com/ctlplne/probectl/internal/agent/metrics"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/endpoint/wire"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/version"
)

type endpointIdentity struct {
	id       crypto.SPIFFEID
	serverCA []byte
	dial     func(string) (*agent.Client, error)
	rotate   func(context.Context, *slog.Logger)
}

func runEnrolled(ctx context.Context, cfg *endpoint.Config, metrics *agentmetrics.Runtime, log *slog.Logger) error {
	identity, err := loadEndpointIdentity(cfg)
	if err != nil {
		return err
	}
	if identity == nil {
		return fmt.Errorf("endpoint: enroll the device before starting its control transport")
	}
	client, err := identity.dial(cfg.Control.Address)
	if err != nil {
		return fmt.Errorf("endpoint: open enrolled control connection: %w", err)
	}
	defer func() { _ = client.Close() }()

	process := wire.ManagedProcess{Platform: runtime.GOOS + "/" + runtime.GOARCH}
	if wire.IsManagedPlatform(process.Platform) {
		process.RunID, err = crypto.UUIDv4()
		if err != nil {
			return fmt.Errorf("endpoint: allocate process identity: %w", err)
		}
	}
	registerCtx, registerCancel := context.WithTimeout(ctx, 15*time.Second)
	if process.RunID != "" {
		registerCtx = metadata.AppendToOutgoingContext(registerCtx, wire.ManagedProcessMetadata, process.HeaderValue())
	}
	registered, err := client.Register(registerCtx, &agentv1.RegisterRequest{
		Hostname: cfg.AgentID, AgentVersion: version.Get().Version,
	})
	registerCancel()
	if err != nil {
		return fmt.Errorf("endpoint: register enrolled device: %w", err)
	}
	if registered.GetTenantId() != identity.id.TenantID || registered.GetAgentId() != identity.id.AgentID ||
		!slices.Contains(registered.GetServerCapabilities(), agenttransport.EndpointResultsCapability) {
		return fmt.Errorf("endpoint: control plane did not accept enrolled endpoint results for this identity")
	}
	if !slices.Contains(registered.GetServerCapabilities(), wire.ManagedProcessCapability) {
		process = wire.ManagedProcess{}
	}
	cfg.AgentID = identity.id.AgentID
	runtimeCtx, stop := context.WithCancel(ctx)
	defer stop()
	go identity.rotate(runtimeCtx, log)
	go heartbeatEndpoint(runtimeCtx, client, identity.id.AgentID, process, log)
	collector := endpoint.NewWithEmitter(cfg, endpoint.StreamEmitter{
		Send: func(ctx context.Context, results []*resultv1.Result) error {
			started := time.Now()
			ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			err := client.SendEndpointResults(ctx, results)
			var count uint64
			if err == nil {
				count = uint64(len(results))
			}
			metrics.Publish(count, time.Since(started), err)
			return err
		},
	}, log)
	if metrics == nil {
		return collector.Run(runtimeCtx)
	}
	return metrics.RunTogether(runtimeCtx, collector.Run)
}

func heartbeatEndpoint(ctx context.Context, client *agent.Client, agentID string, process wire.ManagedProcess, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if process.RunID != "" {
				process.Sequence++
				// An unavailable measurement still carries the current process
				// generation and clears previously observed evidence.
				process.ExecutableIdentity, _ = crypto.RunningCodeIdentity()
				requestCtx = metadata.AppendToOutgoingContext(requestCtx, wire.ManagedProcessMetadata, process.HeaderValue())
			}
			_, err := client.Heartbeat(requestCtx, &agentv1.HeartbeatRequest{AgentId: agentID})
			cancel()
			if err != nil && ctx.Err() == nil {
				log.Warn("enrolled endpoint heartbeat failed", "error", err)
			}
		}
	}
}
