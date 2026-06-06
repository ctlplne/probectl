package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// supportBundle is the offline `probectl-control support-bundle` command
// (S-EE4): collect triage-grade, secret-stripped diagnostics from this install
// without a running server — version, redacted config, a database health
// check, and runtime. The richer live bundle is served at
// GET /v1/diagnostics/bundle when the control plane is running.
func supportBundle(args []string) error {
	fs := flag.NewFlagSet("support-bundle", flag.ContinueOnError)
	out := fs.String("o", "", "output file (default: stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// A best-effort database health check (the offline bundle does not start
	// the server, so this is the one live signal).
	dbCheck := support.PingCheck("database", func(ctx context.Context) error {
		db, err := store.Open(ctx, cfg.DatabaseURL, 1, 0, 3*time.Second)
		if err != nil {
			return err
		}
		defer db.Close()
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return db.Ping(c)
	})
	health := support.RunChecks(context.Background(), map[string]support.CheckFunc{"database": dbCheck}, time.Now)

	src := support.Sources{
		Version:        version.Get(),
		ConfigRedacted: cfg.Redacted(),
		Health:         health,
		SelfMetrics:    support.SelfSnapshot(time.Now()),
		Runtime:        support.CollectRuntime(time.Now()),
		Notes:          []string{"Generated offline by `probectl-control support-bundle` — for a live bundle (topology, self-metrics over time) use GET /v1/diagnostics/bundle."},
		RedactValues:   offlineSecrets(cfg),
	}

	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	man, err := support.Generate(w, src)
	if err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "support bundle written to %s (%d files)\n", *out, len(man.Files))
	}
	return nil
}

// offlineSecrets gathers sensitive config values to scrub from the bundle.
func offlineSecrets(c *config.Config) []string {
	cand := []string{c.EnvelopeKey, c.OIDCClientSecret, c.CMDBSecret, c.AIModelToken,
		c.OutageRadarToken, c.ProviderBootstrapToken, c.SIEMToken}
	out := cand[:0]
	for _, v := range cand {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
