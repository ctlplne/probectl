// Package promapi implements probectl's Prometheus-compatible surfaces (S40,
// F30): the Grafana datasource API (a Prometheus HTTP-API subset Grafana's
// native Prometheus datasource speaks), the /federate exposition endpoint, and
// the remote-write ingest decoder.
//
// # The tenant boundary (CLAUDE.md §7)
//
// Every query expression is parsed into a strict series SELECTOR — a metric
// name plus label matchers, nothing else. Arbitrary PromQL (functions,
// operators, subqueries) is rejected, because a query we cannot fully parse is
// a query we cannot tenant-scope. After parsing, ForceTenant strips any caller
// tenant_id matcher and injects tenant_id="<caller's tenant>", so the
// reconstructed selector — never the raw input — is what gets evaluated
// locally or forwarded upstream. Remote-write ingest likewise overwrites any
// tenant_id label in the payload with the authenticated caller's tenant.
//
// Untrusted-input bounds: regex matchers are length-capped and compiled as
// fully-anchored RE2; remote-write payloads are size-, series-, sample-, and
// label-capped; query responses enforce a series-cardinality cap (federation
// cardinality is the sprint's stated risk).
package promapi
