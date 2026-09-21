// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package otlp is probectl's OpenTelemetry OTLP transport (S22): a TLS-only,
// authenticated, tenant-scoped receiver that ingests external OTLP, an exporter
// that emits probectl signals as OTLP, and the signal<->OTLP-metrics conversion.
//
// The signal schema has been OTel-shaped since S6 (internal/otel), so this
// package EXPOSES the canonical resource/attribute mapping rather than remapping
// a divergent model. The receiver is an inbound surface: it requires TLS,
// authenticates and tenant-scopes every push, and treats ingested OTLP as
// untrusted input — it fails closed (docs/guardrails.md G7-12). eBPF flow/L7
// signals already follow OTel network conventions, so OBI's OTLP is ingested
// without a translation shim.
package otlp
