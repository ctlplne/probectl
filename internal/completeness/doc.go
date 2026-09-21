// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package completeness validates the shipped-capability wiring registry and
// renders its deterministic audit ledger. It is release tooling: validation is
// entirely offline and never reads operator telemetry or runtime credentials.
package completeness
