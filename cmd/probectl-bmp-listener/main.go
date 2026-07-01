// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"strings"
	"syscall"

	"github.com/imfeelingtheagi/probectl/internal/bgp"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	probectlc "github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
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
	collector := fs.String("collector", envOr("PROBECTL_BMP_COLLECTOR", "bmp"), "collector id written on BGP events")
	busMode := fs.String("bus-mode", envOr("PROBECTL_BMP_BUS_MODE", "memory"), "result bus mode: memory|kafka")
	busBrokers := fs.String("bus-brokers", os.Getenv("PROBECTL_BMP_BUS_BROKERS"), "comma-separated Kafka brokers")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}
	if *listenAddr == "" {
		return fmt.Errorf("PROBECTL_BMP_LISTEN_ADDR or --listen is required")
	}
	if *certFile == "" || *keyFile == "" || *caFile == "" {
		return fmt.Errorf("BMP listener requires --tls-cert, --tls-key, and --tls-ca")
	}

	log := logging.New(os.Stdout, envOr("PROBECTL_BMP_LOG_LEVEL", "info"), envOr("PROBECTL_BMP_LOG_FORMAT", "json"))
	if err := probectlc.RunPowerOnSelfTest(log); err != nil {
		return err
	}

	tlsCfg, err := probectlc.ServerMTLSConfig(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", *listenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("bgp bmp: listen: %w", err)
	}
	defer func() { _ = ln.Close() }()

	b, err := bus.New(*busMode, splitCSV(*busBrokers), bus.SecurityFromEnv(os.Getenv, "PROBECTL_BMP_BUS"))
	if err != nil {
		return err
	}
	defer func() { _ = b.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("bmp listener starting", "addr", ln.Addr().String(), "collector", *collector, "bus_mode", *busMode)
	return bgp.NewBMPListener(ln, b, *collector, log).Serve(ctx)
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
