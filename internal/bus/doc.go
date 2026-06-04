// Package bus is probectl's result/event transport (S6). Kafka is the default; an
// in-memory bus backs the lightweight (<5 agent) mode and tests. Payloads are
// Protobuf; topics follow probectl.<type>.results / probectl.<type>.events and are
// tenant-tagged via the partition key (pooled mode). It decouples gRPC ingest
// from storage: ingest publishes, a consumer drains to the TSDB.
package bus
