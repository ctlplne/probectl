// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package browsercanary adapts the browser transaction engine into the standard
// canary plugin interface. Keeping this small bridge outside internal/canary
// avoids an import cycle: browser already maps results onto canary.Result.
package browsercanary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/objectstore"
)

const (
	// Type is the canary/test type accepted by REST, CLI, UI, and the agent.
	Type = "browser"
	// ScriptParam carries the transaction Script JSON in a test's params map.
	ScriptParam = "script"
	// DriverParam states the execution semantics the test requires. An agent
	// configured for another driver rejects the test instead of silently
	// substituting a non-rendering HTTP transaction for a rendered browser.
	DriverParam = "browser_driver"

	DriverHTTP    = "http"
	DriverBrowser = "browser"
)

const defaultWorkerStepTimeout = 15 * time.Second

// DriverConfig selects the agent-local implementation for browser tests.
// WorkerPath is passed as the first argument to WorkerCommand; no listener or
// network control channel is created between the Go agent and Playwright.
type DriverConfig struct {
	Driver        string
	WorkerCommand string
	WorkerPath    string
	WorkerArgs    []string
	StepTimeout   time.Duration
}

// Browser is the schedulable browser/transaction synthetic canary.
type Browser struct {
	target string
	tenant string
	script browser.Script
	fleet  *browser.Fleet
	driver string
}

// New builds a browser canary. If params.script is absent, target is wrapped in
// a minimal transaction: goto target, assert HTTP 200. If params.script is
// present, it is the browser.Script JSON; target is still the server_address
// join key used by result views.
func New(cfg canary.Config) (canary.Canary, error) {
	return newBrowser(cfg, nil, nil, DriverConfig{Driver: DriverHTTP})
}

// newWithObjectStore builds a browser canary factory that stores failure
// artifacts under tenant-scoped object keys. A configured store requires the
// agent runtime to pass TenantID so artifact writes fail closed instead of
// falling back to an unscoped path.
func newWithObjectStore(store objectstore.Store, log *slog.Logger) canary.Factory {
	return func(cfg canary.Config) (canary.Canary, error) {
		return newBrowser(cfg, store, log, DriverConfig{Driver: DriverHTTP})
	}
}

// NewFactory returns the browser factory registered by the shipped agent. In
// rendered mode it verifies both the command and worker script at startup, so
// an incomplete image/config fails closed before any schedules begin.
func NewFactory(driver DriverConfig, store objectstore.Store, log *slog.Logger) (canary.Factory, error) {
	if driver.Driver == "" {
		driver.Driver = DriverHTTP
	}
	switch driver.Driver {
	case DriverHTTP:
	case DriverBrowser:
		if strings.TrimSpace(driver.WorkerCommand) == "" {
			return nil, errors.New("browser: worker command is required for browser driver")
		}
		if _, err := exec.LookPath(driver.WorkerCommand); err != nil {
			return nil, fmt.Errorf("browser: worker command %q is unavailable: %w", driver.WorkerCommand, err)
		}
		if strings.TrimSpace(driver.WorkerPath) == "" {
			return nil, errors.New("browser: worker path is required for browser driver")
		}
		info, err := os.Stat(driver.WorkerPath)
		if err != nil {
			return nil, fmt.Errorf("browser: worker path %q is unavailable: %w", driver.WorkerPath, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("browser: worker path %q is not a regular file", driver.WorkerPath)
		}
		if driver.StepTimeout <= 0 {
			driver.StepTimeout = defaultWorkerStepTimeout
		}
	default:
		return nil, fmt.Errorf("browser: driver must be http or browser (got %q)", driver.Driver)
	}
	return func(cfg canary.Config) (canary.Canary, error) {
		return newBrowser(cfg, store, log, driver)
	}, nil
}

func newBrowser(cfg canary.Config, store objectstore.Store, log *slog.Logger, driver DriverConfig) (canary.Canary, error) {
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		return nil, errors.New("browser: target URL is required")
	}
	tenant := strings.TrimSpace(cfg.TenantID)
	if store != nil && tenant == "" {
		return nil, errors.New("browser: tenant id is required when artifact store is configured")
	}
	s, err := scriptFromConfig(target, cfg.Params)
	if err != nil {
		return nil, err
	}
	guard := canary.GuardFromParams(cfg.Params)
	if err := checkScriptTargets(guard, s); err != nil {
		return nil, err
	}
	requiredDriver := strings.TrimSpace(cfg.Params[DriverParam])
	if requiredDriver == "" {
		// Backward-compatible legacy browser tests were explicitly HTTP-layer
		// transactions. Rendered execution is opt-in and must say so.
		requiredDriver = DriverHTTP
	}
	if requiredDriver != DriverHTTP && requiredDriver != DriverBrowser {
		return nil, fmt.Errorf("browser: %s must be http or browser (got %q)", DriverParam, requiredDriver)
	}
	if requiredDriver != driver.Driver {
		return nil, fmt.Errorf("browser: test requires %s driver but this agent is configured for %s", requiredDriver, driver.Driver)
	}
	runTimeout := cfg.Timeout
	driverFactory := func() browser.Driver {
		if driver.Driver == DriverBrowser {
			args := append([]string{driver.WorkerPath}, driver.WorkerArgs...)
			return browser.NewExecDriver(driver.WorkerCommand, args...).WithEnv(
				"PROBECTL_BROWSER_STEP_TIMEOUT_MS="+strconv.FormatInt(driver.StepTimeout.Milliseconds(), 10),
				"PROBECTL_BROWSER_ALLOW_PRIVATE_TARGETS="+strconv.FormatBool(cfg.Params[canary.AllowPrivateParam] == "true"),
			)
		}
		return browser.NewHTTPDriver(browser.WithTargetGuard(guard))
	}
	fleet := browser.NewFleet(
		browser.Config{MaxConcurrency: 1, RunTimeout: runTimeout},
		driverFactory,
		store,
		log,
	)
	return &Browser{target: target, tenant: tenant, script: s, fleet: fleet, driver: driver.Driver}, nil
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
	description := "HTTP transaction synthetic (no rendering)"
	if b.driver == DriverBrowser {
		description = "Rendered browser synthetic (Playwright)"
	}
	return canary.Spec{Type: Type, Version: "1", Description: description}
}

// Run executes one browser transaction and maps it onto the canonical result.
func (b *Browser) Run(ctx context.Context) (canary.Result, error) {
	res, err := b.fleet.Run(ctx, b.tenant, b.script)
	if err != nil {
		return canary.Result{}, err
	}
	out := res.ToCanaryResult()
	out.Attributes["browser.driver"] = b.driver
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
