// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package browsercanary adapts the browser transaction engine into the standard
// canary plugin interface. Keeping this small bridge outside internal/canary
// avoids an import cycle: browser already maps results onto canary.Result.
package browsercanary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/browser"
	"github.com/imfeelingtheagi/probectl/internal/canary"
)

const (
	// Type is the canary/test type accepted by REST, CLI, UI, and the agent.
	Type = "browser"
	// ScriptParam carries the transaction Script JSON in a test's params map.
	ScriptParam = "script"
)

// Browser is the schedulable browser/transaction synthetic canary.
type Browser struct {
	target string
	script browser.Script
	fleet  *browser.Fleet
}

// New builds a browser canary. If params.script is absent, target is wrapped in
// a minimal transaction: goto target, assert HTTP 200. If params.script is
// present, it is the browser.Script JSON; target is still the server_address
// join key used by result views.
func New(cfg canary.Config) (canary.Canary, error) {
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		return nil, errors.New("browser: target URL is required")
	}
	s, err := scriptFromConfig(target, cfg.Params)
	if err != nil {
		return nil, err
	}
	guard := canary.GuardFromParams(cfg.Params)
	if err := checkScriptTargets(guard, s); err != nil {
		return nil, err
	}
	runTimeout := cfg.Timeout
	fleet := browser.NewFleet(
		browser.Config{MaxConcurrency: 1, RunTimeout: runTimeout},
		func() browser.Driver { return browser.NewHTTPDriver(browser.WithTargetGuard(guard)) },
		nil,
		nil,
	)
	return &Browser{target: target, script: s, fleet: fleet}, nil
}

func scriptFromConfig(target string, params map[string]string) (browser.Script, error) {
	if raw := strings.TrimSpace(params[ScriptParam]); raw != "" {
		s, err := browser.Parse([]byte(raw))
		if err != nil {
			return browser.Script{}, err
		}
		if strings.TrimSpace(s.StartURL) == "" {
			s.StartURL = target
		}
		return s, nil
	}
	return browser.Script{
		Name:     "browser",
		StartURL: target,
		Steps: []browser.Step{
			{Name: "open", Action: browser.Goto},
			{Name: "status", Action: browser.AssertStatus, Status: 200},
		},
	}, nil
}

func checkScriptTargets(guard *canary.TargetGuard, s browser.Script) error {
	if s.StartURL != "" {
		if err := checkURL(guard, s.StartURL); err != nil {
			return fmt.Errorf("browser: start_url: %w", err)
		}
	}
	for i, st := range s.Steps {
		if st.URL == "" {
			continue
		}
		if err := checkURL(guard, st.URL); err != nil {
			return fmt.Errorf("browser: step %d url: %w", i, err)
		}
	}
	return nil
}

func checkURL(guard *canary.TargetGuard, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("url %q has no host", raw)
	}
	return guard.CheckHost(u.Hostname())
}

// Describe returns the browser canary spec.
func (b *Browser) Describe() canary.Spec {
	return canary.Spec{Type: Type, Version: "1", Description: "Browser transaction synthetic"}
}

// Run executes one browser transaction and maps it onto the canonical result.
func (b *Browser) Run(ctx context.Context) (canary.Result, error) {
	res, err := b.fleet.Run(ctx, "", b.script)
	if err != nil {
		return canary.Result{}, err
	}
	out := res.ToCanaryResult()
	if out.Target == "" {
		out.Target = b.target
	}
	return out, nil
}

// MarshalScript returns the canonical params.script value for simple producers.
func MarshalScript(s browser.Script) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
