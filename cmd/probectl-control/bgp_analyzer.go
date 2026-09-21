// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/logging"
)

const maxAnalyzerConfigBytes = 1 << 20

type bgpAnalyzerRuntime struct {
	process   bgp.AnalyzerProcess
	brokers   []string
	security  bus.Security
	logLevel  string
	logFormat string
}

// runBGPAnalyzer is the shipped sidecar entry point. The Python process reads
// public BGP data and writes JSONL; this Go process is the tenant-bound trust
// boundary that validates and republishes those events to Kafka.
func runBGPAnalyzer(getenv func(string) string) error {
	rt, err := loadBGPAnalyzerRuntime(getenv)
	if err != nil {
		return err
	}
	log := logging.New(os.Stderr, rt.logLevel, rt.logFormat)
	slog.SetDefault(log)

	b, err := bus.New("kafka", rt.brokers, rt.security)
	if err != nil {
		return fmt.Errorf("bgp analyzer bus: %w", err)
	}
	defer b.Close()

	runner, err := bgp.NewAnalyzerRunner(b, rt.process, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("starting tenant-bound bgp analyzer bridge",
		"tenant_id", rt.process.TenantID,
		"source", analyzerSourceName(rt.process.Args),
		"restart", rt.process.Restart,
	)
	return runner.Run(ctx)
}

func loadBGPAnalyzerRuntime(getenv func(string) string) (bgpAnalyzerRuntime, error) {
	configFile := strings.TrimSpace(getenv("PROBECTL_BGP_ANALYZER_CONFIG"))
	if configFile == "" {
		return bgpAnalyzerRuntime{}, errors.New("PROBECTL_BGP_ANALYZER_CONFIG is required")
	}
	tenantID, err := analyzerConfigTenant(configFile)
	if err != nil {
		return bgpAnalyzerRuntime{}, err
	}

	python := strings.TrimSpace(getenv("PROBECTL_BGP_ANALYZER_PYTHON"))
	if python == "" {
		python = "python3"
	}
	module := strings.TrimSpace(getenv("PROBECTL_BGP_ANALYZER_MODULE"))
	if module == "" {
		module = "probectl_analyzer"
	}
	source := strings.ToLower(strings.TrimSpace(getenv("PROBECTL_BGP_ANALYZER_SOURCE")))
	if source == "" {
		return bgpAnalyzerRuntime{}, errors.New("PROBECTL_BGP_ANALYZER_SOURCE is required")
	}
	args := []string{"-m", module, "--config", configFile}
	sourceFile := strings.TrimSpace(getenv("PROBECTL_BGP_ANALYZER_SOURCE_FILE"))
	defaultRestart := false
	switch source {
	case "ris-live":
		args = append(args, "--ris-live")
		defaultRestart = true
	case "mrt", "replay":
		if sourceFile == "" {
			return bgpAnalyzerRuntime{}, fmt.Errorf("PROBECTL_BGP_ANALYZER_SOURCE_FILE is required for source %q", source)
		}
		args = append(args, "--"+source, sourceFile)
	default:
		return bgpAnalyzerRuntime{}, fmt.Errorf("PROBECTL_BGP_ANALYZER_SOURCE must be ris-live, mrt, or replay (got %q)", source)
	}
	restart, err := envBool(getenv("PROBECTL_BGP_ANALYZER_RESTART"), defaultRestart)
	if err != nil {
		return bgpAnalyzerRuntime{}, fmt.Errorf("PROBECTL_BGP_ANALYZER_RESTART: %w", err)
	}

	if mode := strings.TrimSpace(getenv("PROBECTL_BUS_MODE")); mode != "kafka" {
		return bgpAnalyzerRuntime{}, fmt.Errorf("PROBECTL_BUS_MODE must be kafka for the out-of-process analyzer bridge (got %q)", mode)
	}
	brokers := splitNonEmpty(getenv("PROBECTL_BUS_BROKERS"))
	if len(brokers) == 0 {
		return bgpAnalyzerRuntime{}, errors.New("PROBECTL_BUS_BROKERS is required for the analyzer bridge")
	}

	level := strings.ToLower(strings.TrimSpace(getenv("PROBECTL_LOG_LEVEL")))
	if level == "" {
		level = "info"
	}
	format := strings.ToLower(strings.TrimSpace(getenv("PROBECTL_LOG_FORMAT")))
	if format == "" {
		format = "json"
	}
	return bgpAnalyzerRuntime{
		process: bgp.AnalyzerProcess{
			TenantID:   tenantID,
			Executable: python,
			Args:       args,
			Dir:        strings.TrimSpace(getenv("PROBECTL_BGP_ANALYZER_WORKDIR")),
			Env:        analyzerSubprocessEnv(getenv),
			Restart:    restart,
		},
		brokers:   brokers,
		security:  bus.SecurityFromEnv(getenv, "PROBECTL_BUS"),
		logLevel:  level,
		logFormat: format,
	}, nil
}

func analyzerConfigTenant(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open analyzer config: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxAnalyzerConfigBytes+1))
	if err != nil {
		return "", fmt.Errorf("read analyzer config: %w", err)
	}
	if len(data) > maxAnalyzerConfigBytes {
		return "", fmt.Errorf("analyzer config exceeds %d bytes", maxAnalyzerConfigBytes)
	}
	var cfg struct {
		TenantID string `json:"tenant_id"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&cfg); err != nil {
		return "", fmt.Errorf("decode analyzer config: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return "", fmt.Errorf("decode analyzer config: %w", err)
	}
	if strings.TrimSpace(cfg.TenantID) == "" {
		return "", errors.New("analyzer config tenant_id is required")
	}
	return cfg.TenantID, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values are not allowed")
	}
	return err
}

func analyzerSubprocessEnv(getenv func(string) string) []string {
	// Do not hand the Python child the Go bridge's Kafka/DB credentials. It only
	// needs runtime/TLS/proxy variables; Kafka auth remains inside bus.New.
	keys := []string{"PATH", "PYTHONPATH", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}
	env := []string{"PYTHONUNBUFFERED=1"}
	for _, key := range keys {
		if value := getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func envBool(raw string, fallback bool) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return fallback, nil
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("want true or false, got %q", raw)
	}
}

func splitNonEmpty(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func analyzerSourceName(args []string) string {
	for _, arg := range args {
		switch arg {
		case "--ris-live":
			return "ris-live"
		case "--mrt":
			return "mrt"
		case "--replay":
			return "replay"
		}
	}
	return "unknown"
}
