// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"fmt"
	"strings"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/otel/otlp"
	"github.com/ctlplne/probectl/internal/pipeline"
)

// signalExporter is an OTLP export client for all three signals (ARCH-003).
// The concrete otlp.{GRPC,HTTP}Exporter implement it.
type signalExporter interface {
	pipeline.MetricsExporter
	pipeline.TracesExporter
	pipeline.LogsExporter
}

// buildOTLPExporter constructs the configured OTLP export client (ARCH-007,
// ARCH-003: metrics + traces + logs). A remote (non-loopback) endpoint MUST be
// TLS — Insecure is refused for it (guardrail 12); loopback may be plaintext for
// a co-located collector.
func buildOTLPExporter(cfg *config.Config) (signalExporter, error) {
	insecure := cfg.OTLPExportInsecure
	if insecure && !isLoopbackEndpoint(cfg.OTLPExportEndpoint) {
		return nil, fmt.Errorf("PROBECTL_OTLP_EXPORT_INSECURE is only allowed for a loopback endpoint, not %q (guardrail 12)", cfg.OTLPExportEndpoint)
	}
	ec := otlp.ExporterConfig{
		Endpoint: cfg.OTLPExportEndpoint,
		Token:    cfg.OTLPExportToken,
		Insecure: insecure,
	}
	if !insecure {
		// Outbound export to a (possibly third-party) OTLP collector: the hardened
		// client policy from internal/crypto — TLS 1.2 floor (collectors may not be
		// 1.3-only), AEAD-only ciphers, modern curves, cert validation always on
		// (system roots). TLS policy lives only in internal/crypto (WIRE-005).
		ec.TLS = crypto.HardenedClientTLSConfig()
	}
	if cfg.OTLPExportProtocol == "http" {
		return otlp.NewHTTPExporter(ec)
	}
	return otlp.NewGRPCExporter(ec)
}

// isLoopbackEndpoint reports whether the endpoint host is loopback/localhost.
func isLoopbackEndpoint(ep string) bool {
	e := ep
	for _, p := range []string{"https://", "http://", "grpc://"} {
		e = strings.TrimPrefix(e, p)
	}
	host := e
	if i := strings.IndexAny(host, ":/"); i >= 0 {
		host = host[:i]
	}
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
