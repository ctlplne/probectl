// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package tenancy is probectl's tenant boundary — the outermost scope and security
// boundary on every tenant-owned record (F50). It defines the tenant identity
// type and request context, and the InTenant transaction wrapper that is the
// MANDATORY choke point for tenant-scoped data access.
//
// InTenant assumes the least-privilege probectl_app role and sets the
// probectl.tenant_id GUC, so Postgres Row-Level Security scopes every statement to
// the caller's tenant. Pooled isolation is therefore enforced at the storage +
// query layer (defense-in-depth), not by application code alone: a query that
// forgets a predicate still cannot read another tenant's rows, and an absent
// tenant context fails closed (CLAUDE.md §7 guardrail 1).
//
// The provider/management plane operates on global tables via the pool directly
// (no tenant scope); break-glass access to a tenant's data goes through InTenant
// with that tenant's id and is separately audited.
package tenancy
