// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// Source files in ee/ are NOT covered by the root LICENSE (BUSL-1.1 core, MPL-2.0
// client tree). Their source
// is visible for review, but production use requires a valid Enterprise/MSP
// agreement and resale additionally requires an MSP entitlement plus a signed
// reseller agreement. ee/LICENSE is explicitly DRAFT-FOR-COUNSEL until the
// final commercial text is approved.
//
// The boundary rules (CI-enforced by the editions gate):
//   - ee/ may import core packages; core may NEVER import ee/.
//   - A core-only build (with ee/ inert) must pass the entire test suite.
//   - Features here activate only through internal/license entitlements,
//     wired at the main.go Build* seams — never via scattered tier checks.

// Package ee is the root of probectl's commercial tree. It is intentionally
// empty at S-T0: the provider plane (S-T1), siloed isolation (S-T2),
// metering (S-T3), BYOK (S-T6), governance (S-EE3), and
// guarded remediation (S-EE5) land here, each gated by its license feature.
package ee
