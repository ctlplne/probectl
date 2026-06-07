package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/preflight"
)

// runPreflight is the operator deployment self-check (Sprint 8 —
// SEC-002/COMPLY-004): probectl's own at-rest sealing posture plus the
// operator's storage-encryption duties for the bulk telemetry volumes
// (docs/hardening.md). Warnings exit 0 by default; --strict exits 1 so
// regulated profiles and CI can gate on it.
//
//	probectl-control preflight [--strict] [--paths /var/lib/postgresql,/var/lib/clickhouse]
func runPreflight(args []string) error {
	fs := flag.NewFlagSet("preflight", flag.ContinueOnError)
	strict := fs.Bool("strict", false, "exit non-zero on warnings (regulated profiles, CI)")
	paths := fs.String("paths", "/var/lib/probectl",
		"comma-separated data paths whose backing mounts are checked for at-rest encryption")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	var findings []preflight.Finding
	keyConfigured := cfg.EnvelopeKey != "" || cfg.EnvelopeKeyFile != ""
	findings = append(findings, preflight.CheckEnvelopeKey(keyConfigured, cfg.RequireAtRestEncryption))

	attested := strings.EqualFold(os.Getenv("PROBECTL_STORAGE_ENCRYPTION_ATTESTED"), "true")
	mounts, merr := preflight.ReadSelfMounts()
	if merr != nil {
		findings = append(findings, preflight.Finding{
			Check: "storage-encryption", Severity: preflight.Warn,
			Detail: fmt.Sprintf("cannot read /proc/self/mounts (%v) — assess volume encryption manually (docs/hardening.md)", merr)})
	} else {
		var ps []string
		for _, p := range strings.Split(*paths, ",") {
			if p = strings.TrimSpace(p); p != "" {
				ps = append(ps, p)
			}
		}
		findings = append(findings, preflight.CheckStorageEncryption(mounts, ps, attested)...)
	}

	worst := 0
	for _, f := range findings {
		fmt.Printf("[%-4s] %-40s %s\n", strings.ToUpper(string(f.Severity)), f.Check, f.Detail)
		if f.Severity == preflight.Warn {
			worst = 1
		}
	}
	if *strict && worst != 0 {
		return fmt.Errorf("preflight: warnings present and --strict set (operator duties: docs/hardening.md)")
	}
	return nil
}
