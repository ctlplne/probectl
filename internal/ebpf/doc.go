// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package ebpf is the probectl eBPF host agent (S20): zero-instrumentation L3/L4
// flow capture and a live service map — the shared substrate later reused by the
// security, segmentation, and cost planes.
//
// The package is split so the bulk runs and is tested anywhere, kernel or not.
// A pure-Go userspace core (the Flow/ServiceEdge model, the ServiceMap
// aggregator, process/cgroup enrichment, the capability probe, the OTel mapping,
// and the bus emitter) drives a pluggable flow Source. The live Source — a CO-RE
// eBPF program loaded via cilium/ebpf into a ring buffer — is compiled only under
// `//go:build linux && ebpf`; it needs clang at build time and a BTF kernel +
// CAP_BPF at run time (see docs/ebpf-feasibility.md / S19a). Every other build
// uses the FixtureSource, which is also the no-kernel CI path.
//
// eBPF here is observe-only: the agent loads only observation programs
// (tracepoints/kprobes, plus TLS-library uprobes/uretprobes on the consent-gated
// L7 source — see source_live_l7_linux.go and the observeonly_test.go allow-list)
// and never enforcement (CLAUDE.md §7 guardrail 8). Every flow is stamped with
// the agent's bound tenant (F50), and ring-buffer drops are counted and exposed,
// never silent.
package ebpf
