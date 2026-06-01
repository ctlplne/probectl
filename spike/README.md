# spike/ — throwaway de-risking proofs

This directory holds **time-boxed feasibility spikes**: real, runnable proofs
whose deliverable is *knowledge*, not shippable code (per `CLAUDE.md §9`,
"de-risking spikes precede their builds").

Every spike here:

- is a **separate Go module**, intentionally **absent from `go.work`**, so it is
  never built, vetted, linted, coverage-gated, or tested by the production CI;
- is **excluded from the Makefile format/lint scan** (see the `spike` exclusion
  in the `lint-go` / `fmt` targets);
- is **superseded** by the production sprint it de-risks and is **not** promoted
  as-is.

| Spike | Sprint | De-risks | Findings |
|---|---|---|---|
| [`ebpf/`](ebpf) | S19a | F11 · S20 · S21 (eBPF agent) | [`docs/ebpf-feasibility.md`](../docs/ebpf-feasibility.md) |
