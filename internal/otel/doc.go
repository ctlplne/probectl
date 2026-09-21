// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package otel holds probectl's OpenTelemetry semantic-convention mapping. S6 seeds
// the canonical Result -> OTel resource/attribute mapping (ResultAttributes) and
// the convention names, so every signal is OTel-shaped from its first emission
// (docs/otel-mapping.md; a CI conformance test enforces it). S22 builds the OTLP
// receivers/exporters + OBI on top of this — exposing signals as OTLP rather than
// remapping a divergent model.
package otel
