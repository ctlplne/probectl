// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

// Financial selectors are configuration, never retained read authority. An
// omitted At resolves the previous complete period in that exact revision's
// billing calendar, allowing the existing monthly scheduler to advance without
// silently adopting another financial revision or inventing carrier terms.
type CarrierSLAReportSelection struct {
	AgreementID string `json:"agreement_id"`
	Version     string `json:"version"`
	At          string `json:"at,omitempty"`
}

type CarrierSLAReportDefinition struct {
	Selections []CarrierSLAReportSelection `json:"selections"`
}

// Portable templates contain slots, not another tenant's financial IDs. The
// importer must explicitly bind each slot to a current tenant-owned revision.
type CarrierSLAReportManifestSelection struct {
	Slot string `json:"slot"`
	At   string `json:"at,omitempty"`
}

type CarrierSLAReportManifestDefinition struct {
	Selections []CarrierSLAReportManifestSelection `json:"selections"`
}

type CarrierSLAReportAgreementBinding struct {
	AgreementID string `json:"agreement_id"`
	Version     string `json:"version"`
}
