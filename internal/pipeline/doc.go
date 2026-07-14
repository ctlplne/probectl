// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package pipeline is probectl's result pipeline (S6): it converts probe Results to
// OTel-aligned time series (ResultToSeries) and runs the control-plane Consumer
// that drains the result bus and writes to the TSDB. The flow is
// agent -> gRPC StreamResults -> control-plane ingest -> bus -> Consumer -> TSDB.
package pipeline
