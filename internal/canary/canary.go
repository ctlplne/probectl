// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package canary

import (
	"context"
	"fmt"
	"time"
)

// Canary is a compiled-in probe plugin and the load-bearing extension point for
// every measurement type (icmp/tcp/udp/http/dns, S7+). An agent instantiates
// canaries from its configuration and runs them on a schedule.
//
// A probe FAILURE — target unreachable, timeout, bad response — is reported as a
// Result with Success=false and a populated Error, NOT as a returned error, and
// never as a panic (CLAUDE.md §6). A returned error is reserved for an internal
// plugin fault (misconfiguration, an unrecoverable setup problem).
type Canary interface {
	// Describe returns the plugin's static specification.
	Describe() Spec
	// Run performs exactly one measurement.
	Run(ctx context.Context) (Result, error)
}

// Spec is a canary plugin's static description.
type Spec struct {
	Type        string `json:"type"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

// Config configures a canary instance. Plugin-specific options go in Params.
type Config struct {
	Type     string            `json:"type"`
	Target   string            `json:"target"`
	Interval time.Duration     `json:"interval"`
	Timeout  time.Duration     `json:"timeout"`
	Params   map[string]string `json:"params,omitempty"`
	// TenantID is supplied by the agent runtime for tenant-scoped side effects
	// such as object-store artifact prefixes. Result identity is still stamped
	// by the runtime when records are buffered/emitted.
	TenantID string `json:"tenant_id,omitempty"`
	// AllowInsecureSkipVerify is retained only so older in-process callers
	// continue to compile. NewHTTP ignores this legacy opt-in and always rejects
	// insecure_skip_verify=true; certificate verification cannot be disabled.
	// Remove this field at the next public Config schema break.
	AllowInsecureSkipVerify bool `json:"allow_insecure_skip_verify,omitempty"`
}

// Result is one measurement. Identity (tenant/agent) is stamped by the agent
// runtime when the result is buffered/emitted, so canaries stay identity-agnostic.
//
// Metrics are numeric series (promoted to TSDB samples). Attributes are
// non-numeric, low-promotion context (e.g. the continuous-mode drop-timing
// record) carried as OTel attributes on the result, not as metric labels — so
// they never widen TSDB cardinality.
type Result struct {
	Type       string             `json:"type"`
	Target     string             `json:"target"`
	Success    bool               `json:"success"`
	Error      string             `json:"error,omitempty"`
	StartedAt  time.Time          `json:"started_at"`
	Duration   time.Duration      `json:"duration"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
	Attributes map[string]string  `json:"attributes,omitempty"`
}

// Factory builds a canary instance from its configuration.
type Factory func(cfg Config) (Canary, error)

// Registry holds the compiled-in plugin factories. Canaries are explicitly
// registered (no implicit init magic) so the set compiled into a binary is
// obvious.
type Registry struct {
	factories map[string]Factory
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]Factory)}
}

// Register adds a factory for a canary type. It panics on a duplicate type, which
// can only be a programming error at startup.
func (r *Registry) Register(typ string, f Factory) {
	if _, dup := r.factories[typ]; dup {
		panic("canary: duplicate registration for type " + typ)
	}
	r.factories[typ] = f
}

// New instantiates a canary of the given config's type.
func (r *Registry) New(cfg Config) (Canary, error) {
	f, ok := r.factories[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("canary: unknown type %q", cfg.Type)
	}
	return f(cfg)
}

// types returns the registered canary types.
func (r *Registry) types() []string {
	out := make([]string, 0, len(r.factories))
	for t := range r.factories {
		out = append(out, t)
	}
	return out
}
