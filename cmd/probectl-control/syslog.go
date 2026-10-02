// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/siem"
)

// startSyslogSubsystem wires the authenticated, TLS-only, tenant-scoped syslog
// receiver (RTP-09) when it is configured. The listener's TLS policy comes from
// internal/crypto (server cert + client-cert CA, guardrail G7-4); each source
// authenticates by TLS client-certificate subject or HMAC-SHA256 and binds to
// its tenant; accepted lines are persisted through the SAME device ops store the
// API reads at GET /v1/device/syslog. An unauthenticated sender is rejected
// (fail closed, G7-12).
func startSyslogSubsystem(
	ctx context.Context,
	g *errgroup.Group,
	cfg *config.Config,
	srv *control.Server,
	log *slog.Logger,
) error {
	if !cfg.SyslogEnabled() {
		return nil
	}
	var (
		tlsCfg *tls.Config
		err    error
	)
	if cfg.SyslogClientCertRequired() {
		// Client-cert sources: request and verify the client certificate against
		// the operator CA. The per-source subject is matched above the handshake.
		tlsCfg, err = crypto.ServerClientCertTLSConfig(cfg.SyslogTLSCertFile, cfg.SyslogTLSKeyFile, cfg.SyslogTLSCAFile)
	} else {
		// HMAC-only sources: server-authenticated TLS; the signature authenticates.
		tlsCfg, err = crypto.ServerTLSConfig(cfg.SyslogTLSCertFile, cfg.SyslogTLSKeyFile)
	}
	if err != nil {
		return fmt.Errorf("syslog tls: %w", err)
	}
	sources := make([]siem.SyslogSource, 0, len(cfg.SyslogSources))
	for _, s := range cfg.SyslogSources {
		sources = append(sources, siem.SyslogSource{
			Name:             s.Name,
			TenantID:         s.TenantID,
			Address:          s.Address,
			HMACSecret:       s.HMACSecret,
			TLSClientSubject: s.TLSClientSubject,
			RateLimit:        s.RateLimit,
		})
	}
	receiver, err := siem.NewSyslogReceiver(siem.SyslogReceiverConfig{
		TenantID:     cfg.SyslogDefaultTenantID,
		Sources:      sources,
		MaxLineBytes: cfg.SyslogMaxLineBytes,
		Log:          log,
	}, control.NewDeviceSyslogSink(srv.DeviceOps()))
	if err != nil {
		return fmt.Errorf("syslog receiver: %w", err)
	}
	addr := cfg.SyslogListenAddr
	g.Go(func() error {
		return superviseRestart(ctx, "syslog-receiver", log, func(ctx context.Context) error {
			return receiver.ListenTLS(ctx, addr, tlsCfg)
		})
	})
	log.Info("syslog receiver enabled (authenticated TLS ingest → device syslog)",
		"addr", addr, "sources", len(sources), "client_cert", cfg.SyslogClientCertRequired())
	return nil
}
