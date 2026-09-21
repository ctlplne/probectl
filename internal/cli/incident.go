// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/httpbody"
)

const maxEvidencePackageBytes = 64 << 20

func cmdIncident(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "help" {
		printIncidentUsage(stderr)
		return 2
	}
	switch args[0] {
	case "export":
		return cmdIncidentExport(cfg, args[1:], stdout, stderr)
	case "verify":
		return cmdIncidentVerify(args[1:], stdout, stderr)
	case "ungroup":
		return cmdIncidentCorrelationOverride(cfg, false, args[1:], stdout, stderr)
	case "reverse-override":
		return cmdIncidentCorrelationOverride(cfg, true, args[1:], stdout, stderr)
	default:
		return cmdSurface(cfg, surfaceCommands["incident"], args, stdout, stderr)
	}
}

func printIncidentUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  probectl incident export <incident-id> [--out package.json]")
	fmt.Fprintln(w, "  probectl incident verify <package.json> [--trusted-key-fingerprint sha256:...]")
	fmt.Fprintln(w, "  probectl incident ungroup <incident-id> <signal-id> --reason <text>")
	fmt.Fprintln(w, "  probectl incident reverse-override <incident-id> <override-id> --reason <text>")
	fmt.Fprintln(w, "  probectl incident <list|get|update|changes|journal|journal-append|cis|share|shared> ...")
}

func cmdIncidentCorrelationOverride(cfg Config, reverse bool, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || strings.HasPrefix(args[0], "-") || strings.HasPrefix(args[1], "-") {
		if reverse {
			fmt.Fprintln(stderr, "incident reverse-override: expected <incident-id> <override-id> --reason <text>")
		} else {
			fmt.Fprintln(stderr, "incident ungroup: expected <incident-id> <signal-id> --reason <text>")
		}
		return 2
	}
	incidentID, objectID := args[0], args[1]
	name := "incident ungroup"
	if reverse {
		name = "incident reverse-override"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	reason := fs.String("reason", "", "required audit reason")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintf(stderr, "%s: unexpected arguments\n", name)
		return 2
	}
	cleanReason := strings.TrimSpace(*reason)
	if cleanReason == "" {
		fmt.Fprintf(stderr, "%s: --reason is required\n", name)
		return 2
	}

	op := surfaceCommands["incident"].Ops["ungroup"]
	path := strings.ReplaceAll(op.Path, "{id}", url.PathEscape(incidentID))
	body := map[string]string{"signal_id": objectID, "reason": cleanReason}
	if reverse {
		op = surfaceCommands["incident"].Ops["reverse-override"]
		path = strings.ReplaceAll(op.Path, "{id}", url.PathEscape(incidentID))
		path = strings.ReplaceAll(path, "{override_id}", url.PathEscape(objectID))
		body = map[string]string{"reason": cleanReason}
	}
	var out any
	if err := newClient(cfg).do(op.Method, path, body, &out); err != nil {
		return fail(stderr, err)
	}
	return printGeneric(stdout, out, cfg.JSON, op.Method)
}

func cmdIncidentExport(cfg Config, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "incident export: missing <incident-id>")
		return 2
	}
	incidentID := args[0]
	fs := flag.NewFlagSet("incident export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outPath := fs.String("out", "", "write the exact signed package to this owner-only file")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "incident export: unexpected arguments")
		return 2
	}
	path := strings.ReplaceAll(surfaceCommands["incident"].Ops["export"].Path, "{id}", url.PathEscape(incidentID))
	raw, err := newClient(cfg).raw(http.MethodPost, path, nil, maxEvidencePackageBytes)
	if err != nil {
		return fail(stderr, err)
	}
	if _, err := evidence.Verify(raw); err != nil {
		return fail(stderr, fmt.Errorf("server returned an invalid evidence package: %w", err))
	}
	if *outPath == "" {
		_, err = stdout.Write(append(raw, '\n'))
	} else {
		clean := filepath.Clean(*outPath)
		if err = os.WriteFile(clean, raw, 0o600); err == nil {
			fmt.Fprintf(stdout, "exported verified evidence package to %s\n", clean)
		}
	}
	if err != nil {
		return fail(stderr, err)
	}
	return 0
}

func cmdIncidentVerify(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "incident verify: missing <package.json>")
		return 2
	}
	path := args[0]
	fs := flag.NewFlagSet("incident verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	trusted := fs.String("trusted-key-fingerprint", "", "expected out-of-band signer fingerprint")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "incident verify: unexpected arguments")
		return 2
	}
	info, err := os.Stat(path)
	if err != nil {
		return fail(stderr, err)
	}
	if info.Size() > maxEvidencePackageBytes {
		return fail(stderr, fmt.Errorf("evidence package exceeds %d bytes", maxEvidencePackageBytes))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fail(stderr, err)
	}
	manifest, err := evidence.Verify(raw)
	if err != nil {
		return fail(stderr, err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return fail(stderr, err)
	}
	if *trusted != "" && !strings.EqualFold(strings.TrimSpace(*trusted), pkg.Signing.Fingerprint) {
		return fail(stderr, fmt.Errorf("signer fingerprint %s does not match trusted fingerprint %s", pkg.Signing.Fingerprint, *trusted))
	}
	fmt.Fprintf(stdout, "VERIFIED %s package=%s incident=%s evidence=%d signer=%s\n",
		manifest.Contract, manifest.PackageID, manifest.Incident.ID, len(manifest.Evidence), pkg.Signing.Fingerprint)
	if *trusted == "" {
		fmt.Fprintln(stdout, "NOTICE signer integrity is proven; compare the signer fingerprint out of band to prove operator identity")
	}
	return 0
}

func (c *client) raw(method, path string, body any, limit int64) ([]byte, error) {
	var r io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(encoded)
	}
	target, err := resolveAPIURL(c.cfg.BaseURL, path)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, target.String(), r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.probectl.evidence+json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.cfg.SessionCookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: c.cfg.SessionCookie})
	} else if c.cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
	if c.cfg.Tenant != "" {
		req.Header.Set("X-Probectl-Tenant", c.cfg.Tenant)
	}
	_, sensitiveTarget := sensitiveProviderOperationURL(method, target)
	_, sensitivePath := sensitiveProviderOperationPath(method, path)
	sensitive := sensitiveTarget || sensitivePath
	resp, err := c.requestHTTPClient(target, sensitive).Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	readLimit := limit
	if resp.StatusCode/100 != 2 {
		readLimit = maxBufferedErrorResponseBody
	}
	data, err := httpbody.ReadLimited(resp.Body, readLimit)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		if ok, formatted := formatAPIError(data, c.cfg.Locale); ok {
			return nil, formatted
		}
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return data, nil
}
