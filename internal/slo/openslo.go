// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package slo is the S45 (F42) SLO + business-impact engine: OpenSLO-
// compatible SLI/SLO definitions over the network signals probectl already
// collects (synthetic results today; the metricSource model extends to
// path/BGP/flow/DEM streams), error budgets, multi-window multi-burn-rate
// alerting (the Google SRE method), and service/team (business-unit) mapping.
//
// Conformance (the S45 watch-out — conform, don't diverge): definitions are
// the OpenSLO v1 document shape (apiVersion openslo/v1, kind SLO) restricted
// to the subset probectl evaluates — ratioMetric indicators with the
// Occurrences budgeting method over a rolling time window with one target
// objective. Import validates strictly; export emits the same shape, so
// definitions round-trip losslessly between probectl and other OpenSLO
// tooling. Fields outside the subset are rejected loudly, never silently
// dropped.
package slo

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Document is the OpenSLO v1 SLO document (the evaluated subset).
type Document struct {
	APIVersion string   `yaml:"apiVersion" json:"apiVersion"`
	Kind       string   `yaml:"kind" json:"kind"`
	Metadata   Metadata `yaml:"metadata" json:"metadata"`
	Spec       Spec     `yaml:"spec" json:"spec"`
}

// Metadata names the SLO; labels carry the business mapping (team).
type Metadata struct {
	Name        string            `yaml:"name" json:"name"`
	DisplayName string            `yaml:"displayName,omitempty" json:"displayName,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// Spec is the OpenSLO SLO spec subset.
type Spec struct {
	Description     string       `yaml:"description,omitempty" json:"description,omitempty"`
	Service         string       `yaml:"service" json:"service"`
	Indicator       Indicator    `yaml:"indicator" json:"indicator"`
	TimeWindow      []TimeWindow `yaml:"timeWindow" json:"timeWindow"`
	BudgetingMethod string       `yaml:"budgetingMethod" json:"budgetingMethod"`
	Objectives      []Objective  `yaml:"objectives" json:"objectives"`
}

// Indicator is an inline SLI definition.
type Indicator struct {
	Metadata Metadata      `yaml:"metadata" json:"metadata"`
	Spec     IndicatorSpec `yaml:"spec" json:"spec"`
}

// IndicatorSpec carries the ratio metric (good/total).
type IndicatorSpec struct {
	RatioMetric *RatioMetric `yaml:"ratioMetric" json:"ratioMetric"`
}

// RatioMetric is good-over-total.
type RatioMetric struct {
	Good  MetricRef `yaml:"good" json:"good"`
	Total MetricRef `yaml:"total" json:"total"`
}

// MetricRef wraps a metric source.
type MetricRef struct {
	MetricSource MetricSource `yaml:"metricSource" json:"metricSource"`
}

// MetricSource is the probectl source: which synthetic stream feeds the SLI.
// Spec keys: "target" (probe target; trailing '*' wildcard allowed),
// optional "canary_type" (icmp|http|dns|...; empty = any), and for the GOOD
// metric "outcome: success".
type MetricSource struct {
	Type string            `yaml:"type" json:"type"`
	Spec map[string]string `yaml:"spec" json:"spec"`
}

// TimeWindow is a rolling window ("30d", "7d", "1h", ...).
type TimeWindow struct {
	Duration  string `yaml:"duration" json:"duration"`
	IsRolling bool   `yaml:"isRolling" json:"isRolling"`
}

// Objective is the target ratio (0..1).
type Objective struct {
	DisplayName string  `yaml:"displayName,omitempty" json:"displayName,omitempty"`
	Target      float64 `yaml:"target" json:"target"`
}

// SLO is the validated, evaluation-ready form of a Document.
type SLO struct {
	Name        string
	DisplayName string
	Service     string
	Team        string // metadata.labels["team"] — the BU/showback mapping
	Description string

	CanaryType string // "" = any
	Target     string // probe target; trailing '*' = prefix match
	Objective  float64
	Window     time.Duration

	doc Document // the source document (lossless export)
}

// Parse validates one OpenSLO YAML document into an SLO (strict — the
// conformance watch-out: out-of-subset fields fail loudly).
func Parse(raw []byte) (SLO, error) {
	var d Document
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return SLO{}, fmt.Errorf("slo: parse OpenSLO document: %w", err)
	}
	return fromDocument(d)
}

func fromDocument(d Document) (SLO, error) {
	switch {
	case d.APIVersion != "openslo/v1":
		return SLO{}, fmt.Errorf("slo: unsupported apiVersion %q (want openslo/v1)", d.APIVersion)
	case d.Kind != "SLO":
		return SLO{}, fmt.Errorf("slo: unsupported kind %q (want SLO)", d.Kind)
	case d.Metadata.Name == "":
		return SLO{}, fmt.Errorf("slo: metadata.name is required")
	case d.Spec.Service == "":
		return SLO{}, fmt.Errorf("slo %s: spec.service is required", d.Metadata.Name)
	case d.Spec.BudgetingMethod != "Occurrences":
		return SLO{}, fmt.Errorf("slo %s: budgetingMethod %q unsupported (probectl evaluates Occurrences)", d.Metadata.Name, d.Spec.BudgetingMethod)
	case len(d.Spec.TimeWindow) != 1 || !d.Spec.TimeWindow[0].IsRolling:
		return SLO{}, fmt.Errorf("slo %s: exactly one rolling timeWindow is required", d.Metadata.Name)
	case len(d.Spec.Objectives) != 1:
		return SLO{}, fmt.Errorf("slo %s: exactly one objective is required", d.Metadata.Name)
	case d.Spec.Indicator.Spec.RatioMetric == nil:
		return SLO{}, fmt.Errorf("slo %s: indicator must declare a ratioMetric", d.Metadata.Name)
	}
	target := d.Spec.Objectives[0].Target
	if target <= 0 || target >= 1 {
		return SLO{}, fmt.Errorf("slo %s: objective target must be in (0,1)", d.Metadata.Name)
	}
	window, err := ParseWindow(d.Spec.TimeWindow[0].Duration)
	if err != nil {
		return SLO{}, fmt.Errorf("slo %s: %w", d.Metadata.Name, err)
	}
	rm := d.Spec.Indicator.Spec.RatioMetric
	for _, src := range []MetricSource{rm.Good.MetricSource, rm.Total.MetricSource} {
		if src.Type != "probectl" {
			return SLO{}, fmt.Errorf("slo %s: metricSource.type %q unsupported (want probectl)", d.Metadata.Name, src.Type)
		}
	}
	goodSpec, totalSpec := rm.Good.MetricSource.Spec, rm.Total.MetricSource.Spec
	if goodSpec["outcome"] != "success" {
		return SLO{}, fmt.Errorf("slo %s: good metric must declare outcome: success", d.Metadata.Name)
	}
	probeTarget := totalSpec["target"]
	if probeTarget == "" || probeTarget != goodSpec["target"] {
		return SLO{}, fmt.Errorf("slo %s: good and total must share a non-empty target", d.Metadata.Name)
	}
	if goodSpec["canary_type"] != totalSpec["canary_type"] {
		return SLO{}, fmt.Errorf("slo %s: good and total must share canary_type", d.Metadata.Name)
	}
	return SLO{
		Name:        d.Metadata.Name,
		DisplayName: d.Metadata.DisplayName,
		Service:     d.Spec.Service,
		Team:        d.Metadata.Labels["team"],
		Description: d.Spec.Description,
		CanaryType:  totalSpec["canary_type"],
		Target:      probeTarget,
		Objective:   target,
		Window:      window,
		doc:         d,
	}, nil
}

// Export emits the SLO back as its OpenSLO v1 YAML document (lossless: the
// original document is preserved through import).
func (s SLO) Export() ([]byte, error) {
	out, err := yaml.Marshal(s.doc)
	if err != nil {
		return nil, fmt.Errorf("slo: export %s: %w", s.Name, err)
	}
	return out, nil
}

// Matches reports whether a synthetic result feeds this SLI.
func (s SLO) Matches(canaryType, target string) bool {
	if s.CanaryType != "" && s.CanaryType != canaryType {
		return false
	}
	return s.TargetMatches(target)
}

// TargetMatches checks only the probe target (trailing '*' = prefix match) —
// used by the S43 what-if seam, where canary type is irrelevant.
func (s SLO) TargetMatches(target string) bool {
	if strings.HasSuffix(s.Target, "*") {
		return strings.HasPrefix(target, strings.TrimSuffix(s.Target, "*"))
	}
	return s.Target == target
}

// ParseWindow parses OpenSLO durations: "30d", "4w", "12h", "30m", "90s".
func ParseWindow(raw string) (time.Duration, error) {
	if len(raw) < 2 {
		return 0, fmt.Errorf("slo: invalid duration %q", raw)
	}
	unit := raw[len(raw)-1]
	n, err := strconv.Atoi(raw[:len(raw)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("slo: invalid duration %q", raw)
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'w':
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("slo: invalid duration unit in %q (want s|m|h|d|w)", raw)
}
