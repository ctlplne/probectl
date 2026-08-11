// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package completeness validates the shipped-capability wiring registry and
// renders its deterministic audit ledger. It is release tooling: validation is
// entirely offline and never reads operator telemetry or runtime credentials.
package completeness
