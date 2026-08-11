// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// RegistrySchema is the only accepted capabilities.yaml schema.
	RegistrySchema = "probectl.capabilities/v1"
	// ReleaseCatalogPath is the canonical catalog whose capability rows must
	// agree with the independent completeness denominator policy.
	ReleaseCatalogPath = "docs/claims/release-catalog.json"
	// DenominatorPolicyPath independently binds the release catalog IDs that
	// must remain kind=capability.
	DenominatorPolicyPath = "docs/claims/completeness-denominator.json"
	// NoneByDesignPolicyPath lists the exact capability/cell exclusions that
	// release validation permits.
	NoneByDesignPolicyPath = "docs/claims/completeness-none-by-design.json"
	// RealStackProofCatalogPath binds exact tests to capabilities and CI profiles.
	RealStackProofCatalogPath = "test/real-stack-proofs.json"
	// LedgerSchema identifies the rendered machine-readable artifact.
	LedgerSchema = "probectl.completeness-ledger/v1"
)

// CellNames is the ordered wiring spine used by validation and rendering.
var CellNames = []string{
	"engine",
	"binary",
	"api",
	"cli",
	"ui",
	"docs",
	"config_keys",
	"telemetry",
	"real_stack_proof",
	"migration",
}

// Registry is the single source of truth for capability wiring evidence.
type Registry struct {
	Schema        string       `yaml:"schema"`
	SourceCatalog string       `yaml:"source_catalog"`
	Capabilities  []Capability `yaml:"capabilities"`
}

// Capability is one shipped or deliberately excluded product capability.
type Capability struct {
	ID             string            `yaml:"id"`
	Name           string            `yaml:"name"`
	Status         string            `yaml:"status"`
	EvidenceStatus string            `yaml:"evidence_status,omitempty"`
	Owner          string            `yaml:"owner"`
	UIAliases      map[string]string `yaml:"ui_aliases,omitempty"`
	Engine         Cell              `yaml:"engine"`
	Binary         Cell              `yaml:"binary"`
	API            Cell              `yaml:"api"`
	CLI            Cell              `yaml:"cli"`
	UI             Cell              `yaml:"ui"`
	Docs           Cell              `yaml:"docs"`
	ConfigKeys     Cell              `yaml:"config_keys"`
	Telemetry      Cell              `yaml:"telemetry"`
	RealStackProof Cell              `yaml:"real_stack_proof"`
	Migration      Cell              `yaml:"migration"`
}

// EffectiveEvidenceStatus defaults legacy and complete rows to complete.
func (c Capability) EffectiveEvidenceStatus() string {
	if strings.TrimSpace(c.EvidenceStatus) == "" {
		return "complete"
	}
	return strings.TrimSpace(c.EvidenceStatus)
}

// Cell contains exactly one of concrete evidence references, an explicit
// none-by-design reason, or an acknowledged delivery-evidence gap. A gap means
// "not done" and never counts as spine coverage.
type Cell struct {
	Refs         []string `yaml:"refs,omitempty"`
	NoneByDesign string   `yaml:"none_by_design,omitempty"`
	Gap          string   `yaml:"gap,omitempty"`
}

// NamedCells returns the capability's cells in the canonical display order.
func (c Capability) NamedCells() []NamedCell {
	return []NamedCell{
		{Name: "engine", Cell: c.Engine},
		{Name: "binary", Cell: c.Binary},
		{Name: "api", Cell: c.API},
		{Name: "cli", Cell: c.CLI},
		{Name: "ui", Cell: c.UI},
		{Name: "docs", Cell: c.Docs},
		{Name: "config_keys", Cell: c.ConfigKeys},
		{Name: "telemetry", Cell: c.Telemetry},
		{Name: "real_stack_proof", Cell: c.RealStackProof},
		{Name: "migration", Cell: c.Migration},
	}
}

// NamedCell pairs a stable cell name with its registry content.
type NamedCell struct {
	Name string
	Cell Cell
}

// LoadRegistry reads a strict YAML registry. Unknown fields are errors so a
// misspelled spine cell cannot silently disappear from the gate.
func LoadRegistry(path string) (Registry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Registry{}, fmt.Errorf("read registry: %w", err)
	}
	return DecodeRegistry(data)
}

// DecodeRegistry strictly decodes registry YAML.
func DecodeRegistry(data []byte) (Registry, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var registry Registry
	if err := dec.Decode(&registry); err != nil {
		return Registry{}, fmt.Errorf("decode registry: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return Registry{}, fmt.Errorf("decode registry: multiple YAML documents are not allowed")
	} else if err != io.EOF {
		return Registry{}, fmt.Errorf("decode registry trailing content: %w", err)
	}
	sort.SliceStable(registry.Capabilities, func(i, j int) bool {
		return capabilityLess(registry.Capabilities[i].ID, registry.Capabilities[j].ID)
	})
	return registry, nil
}

func capabilityLess(a, b string) bool {
	var ai, bi int
	if _, err := fmt.Sscanf(a, "F%d", &ai); err == nil && fmt.Sprintf("F%d", ai) == a {
		if _, err := fmt.Sscanf(b, "F%d", &bi); err == nil && fmt.Sprintf("F%d", bi) == b {
			return ai < bi
		}
		return true
	}
	if strings.HasPrefix(b, "F") {
		if _, err := fmt.Sscanf(b, "F%d", &bi); err == nil && fmt.Sprintf("F%d", bi) == b {
			return false
		}
	}
	return a < b
}
