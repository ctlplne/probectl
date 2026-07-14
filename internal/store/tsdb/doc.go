// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tsdb is probectl's time-series writer adapter (S6). It writes generic
// Series (a metric name + labels + a value at a timestamp) to a backend:
// Prometheus remote-write (default; also VictoriaMetrics) or an in-process
// in-memory writer for the lightweight (<5 agent) mode and tests. The
// Result -> Series mapping (OTel-aligned labels) lives in internal/pipeline.
package tsdb
