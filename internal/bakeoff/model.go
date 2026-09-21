// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package bakeoff evaluates evidence-linked buyer scenarios without turning
// missing or unsupported results into numeric zeroes.
package bakeoff

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	CatalogSchemaV1 = "probectl-bakeoff-catalog/v1"
	ProfileSchemaV1 = "probectl-bakeoff-profile/v1"
)

type Catalog struct {
	Schema     string      `json:"schema"`
	Revision   string      `json:"revision"`
	Scenarios  []Scenario  `json:"scenarios"`
	Candidates []Candidate `json:"candidates"`
}

type Scenario struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Fixture            string   `json:"fixture"`
	AcceptanceCriteria []string `json:"acceptance_criteria"`
	Measures           []string `json:"measures"`
	NonGoals           []string `json:"non_goals"`
}

type Candidate struct {
	Name    string   `json:"name"`
	Results []Result `json:"results"`
}

// ResultStatus is deliberately not a number. Only pass/fail enters a score;
// unknown and unsupported remain visible and make the summary ineligible for
// ranking.
type ResultStatus string

const (
	StatusPass        ResultStatus = "pass"
	StatusFail        ResultStatus = "fail"
	StatusUnknown     ResultStatus = "unknown"
	StatusUnsupported ResultStatus = "unsupported"
)

type Result struct {
	ScenarioID string       `json:"scenario_id"`
	Status     ResultStatus `json:"status"`
	Evidence   []Evidence   `json:"evidence"`
	Notes      string       `json:"notes"`
}

type Evidence struct {
	Kind     string `json:"kind"`
	Location string `json:"location"`
	Claim    string `json:"claim"`
}

// Profile contains buyer-owned knobs only. It lives in a separate file so
// changing volumes or weights cannot rewrite candidate facts.
type Profile struct {
	Schema         string             `json:"schema"`
	Revision       string             `json:"revision"`
	BuyerArchetype string             `json:"buyer_archetype"`
	Volumes        map[string]Volume  `json:"volumes"`
	Weights        map[string]float64 `json:"weights"`
}

type Volume struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
	Note  string  `json:"note,omitempty"`
}

type Report struct {
	Schema          string            `json:"schema"`
	CatalogRevision string            `json:"catalog_revision"`
	ProfileRevision string            `json:"profile_revision"`
	BuyerArchetype  string            `json:"buyer_archetype"`
	Volumes         map[string]Volume `json:"volumes"`
	Rows            []Row             `json:"rows"`
	Summaries       []Summary         `json:"summaries"`
}

type Row struct {
	ScenarioID string       `json:"scenario_id"`
	Title      string       `json:"title"`
	Fixture    string       `json:"fixture"`
	Candidate  string       `json:"candidate"`
	Weight     float64      `json:"weight"`
	Status     ResultStatus `json:"status"`
	Evidence   []Evidence   `json:"evidence"`
	Notes      string       `json:"notes"`
}

type Summary struct {
	Candidate        string   `json:"candidate"`
	TotalWeight      float64  `json:"total_weight"`
	AssessedWeight   float64  `json:"assessed_weight"`
	KnownCoverage    float64  `json:"known_coverage"`
	WeightedPassRate *float64 `json:"weighted_pass_rate"`
	RankingEligible  bool     `json:"ranking_eligible"`
	BlockingCells    []string `json:"blocking_cells"`
}

func Evaluate(catalog Catalog, profile Profile) (Report, error) {
	if err := validate(catalog, profile); err != nil {
		return Report{}, err
	}
	report := Report{
		Schema: "probectl-bakeoff-report/v1", CatalogRevision: catalog.Revision,
		ProfileRevision: profile.Revision, BuyerArchetype: profile.BuyerArchetype,
		Volumes: cloneVolumes(profile.Volumes),
	}
	scenarioByID := make(map[string]Scenario, len(catalog.Scenarios))
	for _, scenario := range catalog.Scenarios {
		scenarioByID[scenario.ID] = scenario
	}
	for _, candidate := range catalog.Candidates {
		totalWeight := 0.0
		assessedWeight := 0.0
		passWeight := 0.0
		blocking := make([]string, 0)
		for _, result := range candidate.Results {
			scenario := scenarioByID[result.ScenarioID]
			weight := profile.Weights[scenario.ID]
			totalWeight += weight
			row := Row{
				ScenarioID: scenario.ID, Title: scenario.Title, Fixture: scenario.Fixture,
				Candidate: candidate.Name, Weight: weight, Status: result.Status,
				Evidence: append([]Evidence(nil), result.Evidence...), Notes: result.Notes,
			}
			report.Rows = append(report.Rows, row)
			switch result.Status {
			case StatusPass:
				assessedWeight += weight
				passWeight += weight
			case StatusFail:
				assessedWeight += weight
			case StatusUnknown, StatusUnsupported:
				blocking = append(blocking, scenario.ID+":"+string(result.Status))
			}
		}
		sort.Strings(blocking)
		summary := Summary{
			Candidate: candidate.Name, TotalWeight: totalWeight,
			AssessedWeight: assessedWeight, BlockingCells: blocking,
			RankingEligible: len(blocking) == 0,
		}
		if totalWeight > 0 {
			summary.KnownCoverage = assessedWeight / totalWeight
		}
		if summary.RankingEligible && assessedWeight > 0 {
			rate := passWeight / assessedWeight
			summary.WeightedPassRate = &rate
		}
		report.Summaries = append(report.Summaries, summary)
	}
	return report, nil
}

func validate(catalog Catalog, profile Profile) error {
	if catalog.Schema != CatalogSchemaV1 || profile.Schema != ProfileSchemaV1 {
		return fmt.Errorf("bakeoff: schema mismatch: catalog=%q profile=%q", catalog.Schema, profile.Schema)
	}
	if catalog.Revision == "" || profile.Revision == "" || profile.BuyerArchetype == "" {
		return errors.New("bakeoff: catalog/profile revision and buyer_archetype are required")
	}
	if len(catalog.Scenarios) == 0 || len(catalog.Candidates) == 0 {
		return errors.New("bakeoff: scenarios and candidates are required")
	}
	scenarios := map[string]bool{}
	for _, scenario := range catalog.Scenarios {
		if scenario.ID == "" || scenarios[scenario.ID] {
			return fmt.Errorf("bakeoff: empty or duplicate scenario %q", scenario.ID)
		}
		if scenario.Title == "" || scenario.Fixture == "" || len(scenario.AcceptanceCriteria) == 0 || len(scenario.Measures) == 0 {
			return fmt.Errorf("bakeoff: scenario %s lacks a testable fixture, acceptance criteria, or measures", scenario.ID)
		}
		scenarios[scenario.ID] = true
		weight, ok := profile.Weights[scenario.ID]
		if !ok || weight < 0 {
			return fmt.Errorf("bakeoff: scenario %s requires a non-negative buyer weight", scenario.ID)
		}
	}
	for name, volume := range profile.Volumes {
		if strings.TrimSpace(name) == "" || volume.Value < 0 || volume.Unit == "" {
			return fmt.Errorf("bakeoff: invalid buyer volume %q", name)
		}
	}
	seenCandidates := map[string]bool{}
	for _, candidate := range catalog.Candidates {
		if candidate.Name == "" || seenCandidates[candidate.Name] {
			return fmt.Errorf("bakeoff: empty or duplicate candidate %q", candidate.Name)
		}
		seenCandidates[candidate.Name] = true
		seenResults := map[string]bool{}
		for _, result := range candidate.Results {
			if !scenarios[result.ScenarioID] || seenResults[result.ScenarioID] {
				return fmt.Errorf("bakeoff: candidate %s has unknown or duplicate scenario %q", candidate.Name, result.ScenarioID)
			}
			seenResults[result.ScenarioID] = true
			switch result.Status {
			case StatusPass, StatusFail:
				if len(result.Evidence) == 0 {
					return fmt.Errorf("bakeoff: candidate %s scenario %s has scored status without evidence", candidate.Name, result.ScenarioID)
				}
			case StatusUnknown, StatusUnsupported:
				// Explicit, visible, and intentionally unscored.
			default:
				return fmt.Errorf("bakeoff: candidate %s scenario %s has invalid status %q", candidate.Name, result.ScenarioID, result.Status)
			}
			for _, evidence := range result.Evidence {
				if evidence.Kind == "" || evidence.Location == "" || evidence.Claim == "" {
					return fmt.Errorf("bakeoff: candidate %s scenario %s has incomplete evidence", candidate.Name, result.ScenarioID)
				}
			}
		}
		if len(seenResults) != len(scenarios) {
			return fmt.Errorf("bakeoff: candidate %s has %d results for %d scenarios", candidate.Name, len(seenResults), len(scenarios))
		}
	}
	return nil
}

func cloneVolumes(in map[string]Volume) map[string]Volume {
	out := make(map[string]Volume, len(in))
	for name, volume := range in {
		out[name] = volume
	}
	return out
}
