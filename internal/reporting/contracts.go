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

// DDoSReportDefinition cites one retained observation in the tenant's incident.
type DDoSReportDefinition struct {
	IncidentID         string `json:"incident_id"`
	RuleID             string `json:"rule_id"`
	ReceiptFingerprint string `json:"receipt_fingerprint"`
}

type DashboardDefinition struct {
	DDoSReport          *DDoSReportDefinition       `json:"ddos_report,omitempty"`
	CarrierClaim        *CarrierSLAReportDefinition `json:"carrier_claim,omitempty"`
	ComplianceControl   string                      `json:"compliance_control,omitempty"`
	ComplianceFlow      *ComplianceFlowDefinition   `json:"compliance_flow,omitempty"`
	ClientReport        *ClientReportDefinition     `json:"client_report,omitempty"`
	FlowSources         []FlowSourceRef             `json:"flow_sources,omitempty"`
	AbsoluteFrom        time.Time                   `json:"absolute_from"`
	AbsoluteTo          time.Time                   `json:"absolute_to"`
	Provenance          []string                    `json:"provenance"`
	RedactionState      string                      `json:"redaction_state"`
	CoverageLimitations []string                    `json:"coverage_limitations"`
	Metrics             map[string]string           `json:"metrics"`
}

type ComplianceFlowSource struct {
	ContextID string `json:"context_id"`
	EntityID  string `json:"entity_id"`
}

type ComplianceFlowDefinition struct {
	Lookback      string                 `json:"lookback"`
	Policy        string                 `json:"policy,omitempty"`
	ProtectedZone string                 `json:"protected_zone,omitempty"`
	Sources       []ComplianceFlowSource `json:"sources"`
}

type ComplianceFlowManifestDefinition struct {
	Lookback          string   `json:"lookback"`
	Slots             []string `json:"source_slots"`
	PolicySlot        string   `json:"policy_slot,omitempty"`
	ProtectedZoneSlot string   `json:"protected_zone_slot,omitempty"`
}

type ComplianceFlowManifestBindings struct {
	Sources       map[string]ComplianceFlowSource `json:"sources"`
	Policy        string                          `json:"policy,omitempty"`
	ProtectedZone string                          `json:"protected_zone,omitempty"`
}

func (d DashboardDefinition) HasSources() bool {
	return len(d.FlowSources) != 0 || d.ClientReport != nil || d.CarrierClaim != nil || d.ComplianceControl != "" || d.DDoSReport != nil
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
	CarrierClaim        *CarrierSLAReportManifestDefinition `json:"carrier_claim,omitempty"`
	ComplianceControl   string                              `json:"compliance_control,omitempty"`
	ComplianceFlow      *ComplianceFlowManifestDefinition   `json:"compliance_flow,omitempty"`
	ClientReport        *ClientReportDefinition             `json:"client_report,omitempty"`
	FlowSources         []DashboardManifestFlowSource       `json:"flow_sources,omitempty"`
	AbsoluteFrom        time.Time                           `json:"absolute_from"`
	AbsoluteTo          time.Time                           `json:"absolute_to"`
	Provenance          []string                            `json:"provenance"`
	RedactionState      string                              `json:"redaction_state"`
	CoverageLimitations []string                            `json:"coverage_limitations"`
	Metrics             []DashboardManifestMetric           `json:"metrics"`
}

type DashboardManifestMetric struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type DashboardManifestFlowSource struct {
	Slot string `json:"slot"`
}

type DashboardManifestImportInput struct {
	AgreementBindings  map[string]CarrierSLAReportAgreementBinding `json:"agreement_bindings,omitempty"`
	SourceBindings     map[string]FlowSourceRef                    `json:"source_bindings,omitempty"`
	ComplianceBindings *ComplianceFlowManifestBindings             `json:"compliance_bindings,omitempty"`
	Manifest           DashboardManifest                           `json:"manifest"`
	Confirm            bool                                        `json:"confirm"`
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
	ProviderTriggerAllowed bool      `json:"provider_trigger_allowed,omitempty"`
	DashboardID            string    `json:"dashboard_id"`
	Name                   string    `json:"name"`
	Format                 string    `json:"format"`
	Cadence                string    `json:"cadence"`
	DestinationID          string    `json:"destination_id"`
	FirstRunAt             time.Time `json:"first_run_at"`
}

type ReportGenerateInput struct {
	DashboardID string `json:"dashboard_id"`
	Format      string `json:"format"`
}

// ReportEmailDelivery exposes operational state only, never credentials or body.
type ReportEmailDelivery struct {
	DestinationID string     `json:"destination_id"`
	State         string     `json:"state"`
	Attempts      int64      `json:"attempts"`
	NextAttemptAt *time.Time `json:"next_attempt_at,omitempty"`
	DeliveredAt   *time.Time `json:"delivered_at,omitempty"`
}
