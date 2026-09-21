// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package pipeline is probectl's result pipeline (S6): it converts probe Results to
// OTel-aligned time series (ResultToSeries) and runs the control-plane Consumer
// that drains the result bus and writes to the TSDB. The flow is
// agent -> gRPC StreamResults -> control-plane ingest -> bus -> Consumer -> TSDB.
package pipeline
