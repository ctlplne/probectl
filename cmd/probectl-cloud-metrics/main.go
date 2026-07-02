// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl-cloud-metrics imports already-exported cloud metric rows
// into a self-hosted probectl control plane through /v1/prometheus/write.
// It does not call AWS, Azure, or Google APIs.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/cloudmetrics"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("probectl-cloud-metrics", version.Get())
			return
		}
	}
	if err := run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "probectl-cloud-metrics:", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdin io.Reader, stdout io.Writer) error {
	fs := flag.NewFlagSet("probectl-cloud-metrics", flag.ContinueOnError)
	provider := fs.String("provider", envOr(getenv, "PROBECTL_CLOUD_METRICS_PROVIDER", ""), "aws_cloudwatch_export | azure_monitor_export | gcp_cloud_monitoring_export")
	path := fs.String("file", envOr(getenv, "PROBECTL_CLOUD_METRICS_FILE", "-"), "JSONL export path, or - for stdin")
	apiURL := fs.String("url", envOr(getenv, "PROBECTL_API_URL", "https://localhost:8443"), "probectl API base URL")
	tenant := fs.String("tenant", envOr(getenv, "PROBECTL_TENANT", ""), "tenant UUID/header value")
	token := fs.String("token", envOr(getenv, "PROBECTL_API_TOKEN", ""), "Bearer token")
	batchSize := fs.Int("batch-size", envInt(getenv, "PROBECTL_CLOUD_METRICS_BATCH_SIZE", 1000), "remote-write samples per request")
	dryRun := fs.Bool("dry-run", false, "parse and validate without posting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *batchSize <= 0 {
		return fmt.Errorf("batch-size must be positive")
	}
	if strings.TrimSpace(*tenant) == "" {
		return cloudmetrics.ErrNoTenant
	}
	if err := validateAPIURL(*apiURL); err != nil {
		return err
	}
	r, closeFn, err := openInput(*path, stdin)
	if err != nil {
		return err
	}
	defer closeFn()

	series, err := cloudmetrics.Parse(context.Background(), cloudmetrics.Provider(*provider), *tenant, r)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(stdout, "validated %d cloud metric samples for tenant %s\n", len(series), *tenant)
		return nil
	}
	client := crypto.HardenedHTTPClient(30 * time.Second)
	for start := 0; start < len(series); start += *batchSize {
		end := start + *batchSize
		if end > len(series) {
			end = len(series)
		}
		if err := postRemoteWrite(context.Background(), client, *apiURL, *tenant, *token, series[start:end]); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "imported %d cloud metric samples for tenant %s\n", len(series), *tenant)
	return nil
}

func openInput(path string, stdin io.Reader) (io.Reader, func(), error) {
	if path == "" || path == "-" {
		return stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open cloud metrics file: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}

func postRemoteWrite(ctx context.Context, client *http.Client, apiURL, tenant, token string, series []tsdb.Series) error {
	body, err := cloudmetrics.EncodeRemoteWrite(series)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiURL, "/")+"/v1/prometheus/write", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	req.Header.Set("X-Probectl-Tenant", tenant)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post remote-write: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("remote-write status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

func envOr(getenv func(string) string, key, def string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(getenv func(string) string, key string, def int) int {
	if v := getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func validateAPIURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse API URL: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("probectl API URL must be https; http is allowed only for loopback")
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
