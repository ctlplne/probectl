// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package bus is probectl's result/event transport (S6). Kafka is the default; an
// in-memory bus backs the lightweight (<5 agent) mode and tests. Payloads are
// Protobuf; topics follow probectl.<type>.results / probectl.<type>.events and are
// tenant-tagged via the partition key (pooled mode). It decouples gRPC ingest
// from storage: ingest publishes, a consumer drains to the TSDB.
package bus
