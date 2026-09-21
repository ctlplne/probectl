// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

// Framework mappings for the auditor bundle.
//
// These say which REQUIREMENT AREA each evidence section speaks to. They are
// deliberately stated as requirement themes rather than article numbers: an
// article citation is a legal interpretation, the product is not in a position
// to assert one on an operator's behalf, and a fabricated citation in a signed
// document would be worse than no citation at all. An operator who has taken
// that interpretation — with counsel, or from an auditor's own workpapers —
// supplies the reference through Ref and the bundle carries it.
//
// The bundle's own caveats repeat this to the reader, inside the signed bytes,
// so it survives any tooling that drops surrounding prose.

// DefaultFrameworkMappings returns the shipped mapping set: NIS2, DORA and
// GAIA-X requirement areas against the sections that evidence them. Every entry
// is a theme the section genuinely speaks to; none carries an article number.
func DefaultFrameworkMappings() []FrameworkMapping {
	return []FrameworkMapping{
		// NIS2 (EU Directive 2022/2555) — cybersecurity risk-management measures
		// and incident handling for essential and important entities.
		{
			ID: "nis2.risk-management", Framework: "NIS2",
			Area:     "Cybersecurity risk-management measures: access control and network segmentation",
			Sections: []string{SectionIsolation, SectionSegmentation},
		},
		{
			ID: "nis2.cryptography", Framework: "NIS2",
			Area:     "Policies on the use of cryptography",
			Sections: []string{SectionSelfTest},
		},
		{
			ID: "nis2.incident-handling", Framework: "NIS2",
			Area:     "Incident handling: tamper-evident records of what happened and when",
			Sections: []string{SectionAuditChain},
		},
		{
			ID: "nis2.supply-chain", Framework: "NIS2",
			Area:     "Supply-chain security: the identity and provenance of the software in use",
			Sections: []string{SectionProvenance},
		},

		// DORA (EU Regulation 2022/2554) — ICT risk management for financial
		// entities.
		{
			ID: "dora.protection", Framework: "DORA",
			Area:     "ICT protection and prevention: segregation of data and access",
			Sections: []string{SectionIsolation, SectionSegmentation},
		},
		{
			ID: "dora.detection", Framework: "DORA",
			Area:     "Detection of anomalous activity, with records that cannot be altered after the fact",
			Sections: []string{SectionAuditChain},
		},
		{
			ID: "dora.data-lifecycle", Framework: "DORA",
			Area:     "Retention and disposal of ICT data on a defined policy",
			Sections: []string{SectionRetention, SectionDeletion},
		},
		{
			ID: "dora.third-party", Framework: "DORA",
			Area:     "ICT third-party risk: what software, at which version, from which build",
			Sections: []string{SectionProvenance},
		},

		// GAIA-X — Trust Framework criteria for a compliant service offering.
		{
			ID: "gaiax.data-sovereignty", Framework: "GAIA-X",
			Area:     "Data sovereignty: the operator holds the data and controls where it goes",
			Sections: []string{SectionIsolation, SectionRetention},
		},
		{
			ID: "gaiax.transparency", Framework: "GAIA-X",
			Area:     "Transparency: verifiable statements about the service rather than assertions",
			Sections: []string{SectionAuditChain, SectionProvenance},
		},
		{
			ID: "gaiax.portability-erasure", Framework: "GAIA-X",
			Area:     "Portability and deletion on request, with proof that it happened",
			Sections: []string{SectionDeletion},
		},
		{
			ID: "gaiax.cryptography", Framework: "GAIA-X",
			Area:     "Cryptographic protection with a verifiable implementation",
			Sections: []string{SectionSelfTest},
		},
	}
}
