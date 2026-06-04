// Package testspec is the canonical schema for a probectl synthetic-test
// (canary) configuration: the field set, the valid types, defaults, and
// validation. It is dependency-free so every producer of a test config — the
// REST API (S9), AI test authoring + auto-discovery (S26) — validates against the
// SAME schema, so an authored or discovered config can never be valid in one
// place and rejected in another.
package testspec

import (
	"fmt"
	"sort"
	"strings"
)

// Spec is a synthetic-test configuration.
type Spec struct {
	Name            string            `json:"name"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params,omitempty"`
	Enabled         bool              `json:"enabled"`
}

// ValidTypes is the set of canary types (mirrors the agent's plugin registry).
var ValidTypes = map[string]bool{
	"icmp": true, "tcp": true, "udp": true, "noop": true,
	"dns": true, "http": true, "a2a": true,
}

// Defaults applied by Normalize.
const (
	DefaultIntervalSeconds = 60
	DefaultTimeoutSeconds  = 3
	maxNameLen             = 200
	minInterval            = 1
	maxInterval            = 86400
	minTimeout             = 1
	maxTimeout             = 300
)

// Types returns the valid test types, sorted (for docs / schemas / messages).
func Types() []string {
	out := make([]string, 0, len(ValidTypes))
	for t := range ValidTypes {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Normalize trims fields and applies defaults (interval, timeout), returning a
// copy. It does not validate.
func Normalize(s Spec) Spec {
	s.Name = strings.TrimSpace(s.Name)
	s.Type = strings.TrimSpace(strings.ToLower(s.Type))
	s.Target = strings.TrimSpace(s.Target)
	if s.IntervalSeconds == 0 {
		s.IntervalSeconds = DefaultIntervalSeconds
	}
	if s.TimeoutSeconds == 0 {
		s.TimeoutSeconds = DefaultTimeoutSeconds
	}
	return s
}

// Validate checks the schema rules on a (preferably normalized) spec, returning a
// descriptive error or nil. Messages match the REST API's wording so behavior is
// identical across producers.
func Validate(s Spec) error {
	if s.Name == "" || len(s.Name) > maxNameLen {
		return fmt.Errorf("name is required (1–%d characters)", maxNameLen)
	}
	if !ValidTypes[s.Type] {
		return fmt.Errorf("type must be one of icmp, tcp, udp, dns, http, a2a, noop")
	}
	if s.Type != "noop" && s.Target == "" {
		return fmt.Errorf("target is required")
	}
	if s.IntervalSeconds < minInterval || s.IntervalSeconds > maxInterval {
		return fmt.Errorf("interval_seconds must be between %d and %d", minInterval, maxInterval)
	}
	if s.TimeoutSeconds < minTimeout || s.TimeoutSeconds > maxTimeout {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minTimeout, maxTimeout)
	}
	return nil
}

// Clean normalizes then validates, returning the cleaned spec or a validation
// error. This is the one call producers should use.
func Clean(s Spec) (Spec, error) {
	n := Normalize(s)
	if err := Validate(n); err != nil {
		return Spec{}, err
	}
	return n, nil
}
