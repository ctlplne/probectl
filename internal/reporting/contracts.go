// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import "time"

// These bounded configuration contracts are shared by REST and native tools.
// Source identities describe destination configuration, never stored grants.
type FlowSourceRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type DashboardDefinition struct {
	FlowSources         []FlowSourceRef   `json:"flow_sources,omitempty"`
	AbsoluteFrom        time.Time         `json:"absolute_from"`
	AbsoluteTo          time.Time         `json:"absolute_to"`
	Provenance          []string          `json:"provenance"`
	RedactionState      string            `json:"redaction_state"`
	CoverageLimitations []string          `json:"coverage_limitations"`
	Metrics             map[string]string `json:"metrics"`
}

type DashboardCreateInput struct {
	Name       string              `json:"name"`
	Preset     string              `json:"preset"`
	Shared     bool                `json:"shared"`
	Definition DashboardDefinition `json:"definition"`
}

type DashboardManifest struct {
	APIVersion string                    `json:"api_version"`
	Kind       string                    `json:"kind"`
	Metadata   DashboardManifestMetadata `json:"metadata"`
	Spec       DashboardManifestSpec     `json:"spec"`
}

type DashboardManifestMetadata struct {
	Name string `json:"name"`
}

type DashboardManifestSpec struct {
	Preset     string                      `json:"preset"`
	Shared     bool                        `json:"shared"`
	Definition DashboardManifestDefinition `json:"definition"`
}

type DashboardManifestDefinition struct {
	FlowSources         []DashboardManifestFlowSource `json:"flow_sources,omitempty"`
	AbsoluteFrom        time.Time                     `json:"absolute_from"`
	AbsoluteTo          time.Time                     `json:"absolute_to"`
	Provenance          []string                      `json:"provenance"`
	RedactionState      string                        `json:"redaction_state"`
	CoverageLimitations []string                      `json:"coverage_limitations"`
	Metrics             []DashboardManifestMetric     `json:"metrics"`
}

type DashboardManifestMetric struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DashboardManifestFlowSource struct {
	Slot string `json:"slot"`
}

type DashboardManifestImportInput struct {
	SourceBindings map[string]FlowSourceRef `json:"source_bindings,omitempty"`
	Manifest       DashboardManifest        `json:"manifest"`
	Confirm        bool                     `json:"confirm"`
}

type DashboardManifestPreview struct {
	SourceCount             int       `json:"source_count,omitempty"`
	Name                    string    `json:"name"`
	Preset                  string    `json:"preset"`
	Shared                  bool      `json:"shared"`
	AbsoluteFrom            time.Time `json:"absolute_from"`
	AbsoluteTo              time.Time `json:"absolute_to"`
	MetricCount             int       `json:"metric_count"`
	ProvenanceCount         int       `json:"provenance_count"`
	CoverageLimitationCount int       `json:"coverage_limitation_count"`
}

type ReportScheduleInput struct {
	DashboardID   string    `json:"dashboard_id"`
	Name          string    `json:"name"`
	Format        string    `json:"format"`
	Cadence       string    `json:"cadence"`
	DestinationID string    `json:"destination_id"`
	FirstRunAt    time.Time `json:"first_run_at"`
}

type ReportGenerateInput struct {
	DashboardID string `json:"dashboard_id"`
	Format      string `json:"format"`
}
