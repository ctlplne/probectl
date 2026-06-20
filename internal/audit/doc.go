// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package audit is probectl's immutable, tamper-evident audit log. It keeps two
// SEPARATE hash-chained streams (CLAUDE.md §7 guardrail 7):
//
//   - the tenant stream (audit_events), one chain per tenant, written within a
//     tenancy.Scope so Row-Level Security confines it; and
//   - the provider stream (provider_audit_events), a single global chain for
//     provider-plane and break-glass actions.
//
// Each record's hash chains over the previous record's hash (via internal/crypto),
// so altering, reordering, or deleting any record breaks verification. The tenant
// audit table is append-only for the application role (S2 migration: SELECT/INSERT
// policies, no UPDATE/DELETE). Subject erasure is handled as an append-only
// projection marker: old rows remain verifiable, while normal reads/export replace
// exact structured subject matches with an erased token. WORM provider exports are
// minimized by default so object-locked copies do not carry raw actor/data values.
package audit
