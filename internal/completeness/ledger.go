// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package completeness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ledger is the deterministic, machine-readable projection of a registry.
type Ledger struct {
	Schema        string             `json:"schema"`
	Source        string             `json:"source"`
	SourceCatalog string             `json:"source_catalog"`
	Summary       LedgerSummary      `json:"summary"`
	Capabilities  []LedgerCapability `json:"capabilities"`
}

// LedgerSummary counts every explicit wiring disposition.
type LedgerSummary struct {
	Capabilities                 int `json:"capabilities"`
	FullyDispositioned           int `json:"fully_dispositioned"`
	DeliveredCapabilities        int `json:"delivered_capabilities"`
	PartialCapabilities          int `json:"partial_capabilities"`
	FutureCapabilities           int `json:"future_capabilities"`
	RemovedCapabilities          int `json:"removed_capabilities"`
	EvidenceCompleteCapabilities int `json:"evidence_complete_capabilities"`
	EvidencePartialCapabilities  int `json:"evidence_partial_capabilities"`
	TotalCells                   int `json:"total_cells"`
	WiredCells                   int `json:"wired_cells"`
	NoneByDesignCells            int `json:"none_by_design_cells"`
	GapCells                     int `json:"gap_cells"`
}

// LedgerCapability is one row in the rendered ledger.
type LedgerCapability struct {
	ID             string                `json:"id"`
	Name           string                `json:"name"`
	Status         string                `json:"status"`
	EvidenceStatus string                `json:"evidence_status"`
	Owner          string                `json:"owner"`
	UIAliases      []LedgerUIAlias       `json:"ui_aliases,omitempty"`
	Cells          map[string]LedgerCell `json:"cells"`
}

// LedgerUIAlias makes an explicitly approved cross-capability UI reuse visible
// in both machine-readable and human-readable ledger artifacts.
type LedgerUIAlias struct {
	FeatureID string `json:"feature_id"`
	Reason    string `json:"reason"`
}

// LedgerCell records whether a spine cell is wired or deliberately absent.
type LedgerCell struct {
	State    string   `json:"state"`
	Evidence []string `json:"evidence,omitempty"`
	Reason   string   `json:"reason,omitempty"`
}

// NewLedger projects the registry without clocks, host paths, or other
// nondeterministic values, so identical source produces byte-identical output.
func NewLedger(source string, registry Registry) Ledger {
	ledger := Ledger{
		Schema:        LedgerSchema,
		Source:        filepath.ToSlash(source),
		SourceCatalog: filepath.ToSlash(registry.SourceCatalog),
		Capabilities:  make([]LedgerCapability, 0, len(registry.Capabilities)),
	}
	for _, capability := range registry.Capabilities {
		switch capability.Status {
		case "delivered":
			ledger.Summary.DeliveredCapabilities++
		case "partial":
			ledger.Summary.PartialCapabilities++
		case "future":
			ledger.Summary.FutureCapabilities++
		case "removed":
			ledger.Summary.RemovedCapabilities++
		}
		evidenceStatus := capability.EffectiveEvidenceStatus()
		switch evidenceStatus {
		case "complete":
			ledger.Summary.EvidenceCompleteCapabilities++
		case "partial":
			ledger.Summary.EvidencePartialCapabilities++
		}
		row := LedgerCapability{
			ID:             capability.ID,
			Name:           capability.Name,
			Status:         capability.Status,
			EvidenceStatus: evidenceStatus,
			Owner:          capability.Owner,
			Cells:          make(map[string]LedgerCell, len(CellNames)),
		}
		aliasIDs := make([]string, 0, len(capability.UIAliases))
		for featureID := range capability.UIAliases {
			aliasIDs = append(aliasIDs, featureID)
		}
		sort.Strings(aliasIDs)
		for _, featureID := range aliasIDs {
			row.UIAliases = append(row.UIAliases, LedgerUIAlias{
				FeatureID: featureID,
				Reason:    capability.UIAliases[featureID],
			})
		}
		complete := true
		for _, named := range capability.NamedCells() {
			ledger.Summary.TotalCells++
			if len(named.Cell.Refs) > 0 {
				refs := append([]string(nil), named.Cell.Refs...)
				row.Cells[named.Name] = LedgerCell{State: "wired", Evidence: refs}
				ledger.Summary.WiredCells++
				continue
			}
			if strings.TrimSpace(named.Cell.NoneByDesign) != "" {
				row.Cells[named.Name] = LedgerCell{State: "none-by-design", Reason: named.Cell.NoneByDesign}
				ledger.Summary.NoneByDesignCells++
				continue
			}
			if strings.TrimSpace(named.Cell.Gap) != "" {
				row.Cells[named.Name] = LedgerCell{State: "gap", Reason: named.Cell.Gap}
				ledger.Summary.GapCells++
				complete = false
				continue
			}
			row.Cells[named.Name] = LedgerCell{State: "missing"}
			complete = false
		}
		if complete {
			ledger.Summary.FullyDispositioned++
		}
		ledger.Capabilities = append(ledger.Capabilities, row)
	}
	ledger.Summary.Capabilities = len(ledger.Capabilities)
	return ledger
}

// LedgerGap is one acknowledged gap cell: the row that -require-complete
// refuses a release on, together with the reason the registry recorded for it.
type LedgerGap struct {
	Capability string `json:"capability"`
	Name       string `json:"name"`
	Cell       string `json:"cell"`
	Owner      string `json:"owner"`
	Reason     string `json:"reason"`
}

// Gaps lists every acknowledged gap cell in registry order, then wiring-spine
// order, so the strict release gate can name each blocking row instead of
// printing a bare count an operator cannot act on. The returned length always
// equals Summary.GapCells.
func (l Ledger) Gaps() []LedgerGap {
	gaps := make([]LedgerGap, 0, l.Summary.GapCells)
	for _, capability := range l.Capabilities {
		for _, name := range CellNames {
			cell, ok := capability.Cells[name]
			if !ok || cell.State != "gap" {
				continue
			}
			gaps = append(gaps, LedgerGap{
				Capability: capability.ID,
				Name:       capability.Name,
				Cell:       name,
				Owner:      capability.Owner,
				Reason:     cell.Reason,
			})
		}
	}
	return gaps
}

// WriteJSON writes a stable, indented JSON ledger.
func WriteJSON(path string, ledger Ledger) error {
	data, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON ledger: %w", err)
	}
	data = append(data, '\n')
	return writeArtifact(path, data)
}

// WriteHTML writes a self-contained, offline HTML ledger.
func WriteHTML(path string, ledger Ledger) error {
	var rendered bytes.Buffer
	if err := ledgerTemplate.Execute(&rendered, struct {
		Ledger Ledger
		Cells  []string
	}{Ledger: ledger, Cells: CellNames}); err != nil {
		return fmt.Errorf("render HTML ledger: %w", err)
	}
	return writeArtifact(path, rendered.Bytes())
}

func writeArtifact(path string, data []byte) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create artifact directory: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

var ledgerTemplate = template.Must(template.New("ledger").Funcs(template.FuncMap{
	"cell":  func(row LedgerCapability, name string) LedgerCell { return row.Cells[name] },
	"label": func(value string) string { return strings.ReplaceAll(value, "_", " ") },
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>probectl capability completeness ledger</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #101418; color: #ecf2f8; }
    body { margin: 0; padding: 1.5rem; }
    h1 { margin: 0 0 .25rem; font-size: 1.55rem; }
    .summary { color: #b8c7d6; margin: 0 0 1rem; }
    .table-wrap { overflow: auto; border: 1px solid #32404d; border-radius: .5rem; }
    table { border-collapse: collapse; width: 100%; min-width: 110rem; font-size: .78rem; }
    th, td { border-bottom: 1px solid #2a3540; border-right: 1px solid #2a3540; padding: .55rem; text-align: left; vertical-align: top; }
    th { position: sticky; top: 0; background: #1c252d; z-index: 1; text-transform: capitalize; }
    th:first-child, td:first-child { position: sticky; left: 0; background: #182027; z-index: 2; }
    th:first-child { z-index: 3; }
    .wired { color: #79d69b; }
    .none-by-design { color: #f0c674; }
    .gap { color: #ff9e64; }
    .missing { color: #ff8282; }
    .aliases { border-top: 1px solid #465563; color: #c8d8e7; margin-top: .55rem; padding-top: .45rem; }
    details { max-width: 18rem; }
    summary { cursor: pointer; font-weight: 650; }
    ul { margin: .35rem 0 0; padding-left: 1.1rem; }
    code { white-space: normal; overflow-wrap: anywhere; }
  </style>
</head>
<body>
  <h1>probectl capability completeness ledger</h1>
  <p class="summary">{{.Ledger.Summary.Capabilities}} capabilities ({{.Ledger.Summary.DeliveredCapabilities}} delivered · {{.Ledger.Summary.PartialCapabilities}} partial · {{.Ledger.Summary.FutureCapabilities}} future · {{.Ledger.Summary.RemovedCapabilities}} removed) · evidence {{.Ledger.Summary.EvidenceCompleteCapabilities}} complete / {{.Ledger.Summary.EvidencePartialCapabilities}} partial · {{.Ledger.Summary.WiredCells}} wired cells · {{.Ledger.Summary.NoneByDesignCells}} explicit none-by-design cells · {{.Ledger.Summary.GapCells}} acknowledged gaps · source <code>{{.Ledger.Source}}</code></p>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Capability</th><th>Status / owner</th>{{range .Cells}}<th>{{label .}}</th>{{end}}</tr></thead>
      <tbody>
      {{range .Ledger.Capabilities}}
        {{$row := .}}
        <tr>
          <td><strong>{{.ID}}</strong><br>{{.Name}}</td>
          <td>{{.Status}}<br>evidence: {{.EvidenceStatus}}<br><code>{{.Owner}}</code></td>
          {{range $.Cells}}
            {{$entry := cell $row .}}
            <td class="{{$entry.State}}"><details><summary>{{$entry.State}}</summary>{{if $entry.Evidence}}<ul>{{range $entry.Evidence}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<p>{{$entry.Reason}}</p>{{end}}</details>{{if and (eq . "ui") $row.UIAliases}}<div class="aliases"><strong>Approved UI aliases</strong><ul>{{range $row.UIAliases}}<li><code>{{.FeatureID}}</code>: {{.Reason}}</li>{{end}}</ul></div>{{end}}</td>
          {{end}}
        </tr>
      {{end}}
      </tbody>
    </table>
  </div>
</body>
</html>
`))
