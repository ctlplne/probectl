// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package flow implements the S38 (F17) passive flow-collection plane: UDP
// collectors for NetFlow v5, NetFlow v9, IPFIX, and sFlow v5 plus local
// cloud-flow importers for AWS VPC Flow Logs, Azure NSG Flow Logs, and GCP VPC
// Flow Logs. Every source decodes into one normalized, tenant-scoped Record and
// publishes batches to the bus (probectl.flow.events) for the control plane to
// enrich (ASN/geo, S15) and persist to ClickHouse
// (internal/store/flowstore).
//
// Design notes:
//
//   - All input is untrusted (CLAUDE.md §7 guardrail 12): every decoder is
//     pure, bounds-checked, allocation-capped, and returns errors instead of
//     panicking. Template state (v9/IPFIX) is TTL'd and size-bounded so a
//     hostile exporter cannot grow memory without bound.
//   - Sampling is handled at decode time: records carry the raw counters, the
//     exporter sampling rate (from the v5 header, v9/IPFIX options templates,
//     or the sFlow sample itself), and pre-scaled estimates for analytics.
//   - NetFlow v9 and IPFIX are template-based: data sets that arrive before
//     their template are counted (template misses) and dropped — the exporter
//     resends templates on its template-refresh cycle.
//
// The collector runs in the dedicated probectl-flow-agent binary (mirroring
// the eBPF and endpoint agents): deployed next to the exporters, bound to a
// single tenant, speaking the same bus contract as every other plane.
package flow
