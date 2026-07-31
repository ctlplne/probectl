// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Command probectl-bmp-listener accepts direct router BMP sessions over mTLS,
// derives the tenant from each peer's SPIFFE client certificate, and publishes
// normalized route observations to probectl.bgp.events.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentmetrics "github.com/imfeelingtheagi/probectl/internal/agent/metrics"
	"github.com/imfeelingtheagi/probectl/internal/bgp"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	probectlc "github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-bmp-listener", version.Get())
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-bmp-listener:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("probectl-bmp-listener", flag.ContinueOnError)
	listenAddr := fs.String("listen", os.Getenv("PROBECTL_BMP_LISTEN_ADDR"), "BMP listen address; required")
	certFile := fs.String("tls-cert", os.Getenv("PROBECTL_BMP_TLS_CERT_FILE"), "server certificate PEM; required")
	keyFile := fs.String("tls-key", os.Getenv("PROBECTL_BMP_TLS_KEY_FILE"), "server key PEM; required")
	caFile := fs.String("tls-ca", os.Getenv("PROBECTL_BMP_TLS_CA_FILE"), "client CA bundle PEM; required")
	databaseURL := fs.String("database-url", os.Getenv("PROBECTL_BMP_DATABASE_URL"), "local probectl PostgreSQL URL used to verify registry-issued router identities; required")
	revocationDatabaseURL := fs.String("revocation-database-url", os.Getenv("PROBECTL_BMP_REVOCATION_DATABASE_URL"), "verify-full PostgreSQL URL for the execute-only BMP revocation snapshot role; required")
	collector := fs.String("collector", envOr("PROBECTL_BMP_COLLECTOR", "bmp"), "collector id written on BGP events")
	busMode := fs.String("bus-mode", envOr("PROBECTL_BMP_BUS_MODE", "memory"), "result bus mode: memory|kafka")
	busBrokers := fs.String("bus-brokers", os.Getenv("PROBECTL_BMP_BUS_BROKERS"), "comma-separated Kafka brokers")
	handshakeTimeoutRaw := fs.String("handshake-timeout", envOr("PROBECTL_BMP_HANDSHAKE_TIMEOUT", bgp.DefaultBMPHandshakeTimeout.String()), "maximum unauthenticated mTLS handshake time")
	readTimeoutRaw := fs.String("read-timeout", envOr("PROBECTL_BMP_READ_TIMEOUT", bgp.DefaultBMPReadTimeout.String()), "maximum time for each authenticated BMP header or payload read")
	maxSessionsRaw := fs.String("max-sessions", envOr("PROBECTL_BMP_MAX_SESSIONS", strconv.Itoa(bgp.DefaultBMPMaxSessions)), "maximum concurrent BMP sessions")
	revocationRefreshRaw := fs.String("revocation-refresh", envOr("PROBECTL_BMP_REVOCATION_REFRESH", defaultBMPRevocationRefresh.String()), "authoritative revocation snapshot refresh interval")
	revocationTimeoutRaw := fs.String("revocation-timeout", envOr("PROBECTL_BMP_REVOCATION_TIMEOUT", defaultBMPRevocationTimeout.String()), "maximum time for one revocation snapshot")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	handshakeTimeout, err := parsePositiveBMPDuration("handshake timeout", *handshakeTimeoutRaw)
	if err != nil {
		return err
	}
	readTimeout, err := parsePositiveBMPDuration("read timeout", *readTimeoutRaw)
	if err != nil {
		return err
	}
	maxSessions, err := parsePositiveBMPInt("max sessions", *maxSessionsRaw)
	if err != nil {
		return err
	}
	revocationRefresh, err := parsePositiveBMPDuration("revocation refresh", *revocationRefreshRaw)
	if err != nil {
		return err
	}
	revocationTimeout, err := parsePositiveBMPDuration("revocation timeout", *revocationTimeoutRaw)
	if err != nil {
		return err
	}
	if *listenAddr == "" {
		return fmt.Errorf("PROBECTL_BMP_LISTEN_ADDR or --listen is required")
	}
	if *certFile == "" || *keyFile == "" || *caFile == "" {
		return fmt.Errorf("BMP listener requires --tls-cert, --tls-key, and --tls-ca")
	}
	if *databaseURL == "" {
		return fmt.Errorf("PROBECTL_BMP_DATABASE_URL or --database-url is required for issued-identity verification")
	}
	if *revocationDatabaseURL == "" {
		return fmt.Errorf("PROBECTL_BMP_REVOCATION_DATABASE_URL or --revocation-database-url is required")
	}
	if err := validateBMPRevocationDatabaseURL(*revocationDatabaseURL); err != nil {
		return err
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_BMP_LOG_LEVEL", "info"), envOr("PROBECTL_BMP_LOG_FORMAT", "json"))
	if err := probectlc.RunPowerOnSelfTest(log); err != nil {
		return err
	}
	build := version.Get()
	metricsRuntime, err := agentmetrics.New("probectl-bmp-listener", build.Version, build.Commit,
		agentmetrics.ConfigFromEnv(os.Getenv, "PROBECTL_BMP", agentmetrics.DefaultBMPAddr))
	if err != nil {
		return err
	}

	registryDB, err := store.Open(context.Background(), *databaseURL, 4, 0, 5*time.Second)
	if err != nil {
		return fmt.Errorf("bgp bmp: open identity registry: %w", err)
	}
	defer registryDB.Close()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = registryDB.Ping(pingCtx)
	pingCancel()
	if err != nil {
		return fmt.Errorf("bgp bmp: identity registry unavailable: %w", err)
	}
	identities := store.NewAgentIdentities(registryDB.Pool())
	revocations := probectlc.NewRevocationList()
	verifyIssued := probectlc.IssuedIdentityVerifier(identities.KnownIssuedIdentity)

	revocationDB, err := store.Open(
		context.Background(),
		*revocationDatabaseURL,
		2,
		0,
		revocationTimeout,
	)
	if err != nil {
		return fmt.Errorf("bgp bmp: open revocation snapshot source: %w", err)
	}
	defer revocationDB.Close()
	revocationPingCtx, revocationPingCancel := context.WithTimeout(
		context.Background(),
		revocationTimeout,
	)
	err = revocationDB.Ping(revocationPingCtx)
	revocationPingCancel()
	if err != nil {
		return fmt.Errorf("bgp bmp: revocation snapshot source unavailable: %w", err)
	}
	feed, err := newBMPRevocationFeed(
		store.NewBMPRevocations(revocationDB.Pool()),
		revocations,
		revocationRefresh,
		revocationTimeout,
		log,
	)
	if err != nil {
		return err
	}
	if err := feed.loadInitialRevocations(context.Background()); err != nil {
		return fmt.Errorf("bgp bmp: refusing to listen without revocation state: %w", err)
	}

	tlsCfg, err := probectlc.ServerBMPMTLSConfigRegisteredRevocable(
		*certFile,
		*keyFile,
		*caFile,
		verifyIssued,
		handshakeTimeout,
		revocations,
	)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", *listenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("bgp bmp: listen: %w", err)
	}
	defer func() { _ = ln.Close() }()

	rawBus, err := bus.New(*busMode, splitCSV(*busBrokers), bus.SecurityFromEnv(os.Getenv, "PROBECTL_BMP_BUS"))
	if err != nil {
		return err
	}
	b := agentmetrics.ObserveBus(rawBus, metricsRuntime)
	defer func() { _ = b.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("bmp listener starting",
		"addr", ln.Addr().String(),
		"collector", *collector,
		"bus_mode", *busMode,
		"handshake_timeout", handshakeTimeout,
		"read_timeout", readTimeout,
		"max_sessions", maxSessions,
		"revocation_refresh", revocationRefresh,
		"revocations_loaded", revocations.Size(),
	)
	return metricsRuntime.RunTogether(ctx, func(ctx context.Context) error {
		go func() {
			_ = feed.Run(ctx)
		}()
		return bgp.NewBMPListener(ln, b, *collector, log,
			bgp.WithBMPHandshakeTimeout(handshakeTimeout),
			bgp.WithBMPReadTimeout(readTimeout),
			bgp.WithBMPMaxSessions(maxSessions),
			bgp.WithBMPSessionMetrics(metricsRuntime),
			bgp.WithBMPRevocationList(revocations),
			bgp.WithBMPIssuedIdentityVerifier(verifyIssued),
		).Serve(ctx)
	})
}

func parsePositiveBMPDuration(label, raw string) (time.Duration, error) {
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("BMP %s %q is invalid: %w", label, raw, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("BMP %s must be positive", label)
	}
	return value, nil
}

func parsePositiveBMPInt(label, raw string) (int, error) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("BMP %s %q is invalid: %w", label, raw, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("BMP %s must be positive", label)
	}
	return value, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
