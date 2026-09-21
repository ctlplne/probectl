// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package bus is probectl's result/event transport (S6). Kafka is the default; an
// in-memory bus backs the lightweight (<5 agent) mode and tests. Payloads are
// Protobuf; topics follow probectl.<type>.results / probectl.<type>.events and are
// tenant-tagged via the partition key (pooled mode). It decouples gRPC ingest
// from storage: ingest publishes, a consumer drains to the TSDB.
package bus
