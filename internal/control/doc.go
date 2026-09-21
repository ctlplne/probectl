// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package control implements the probectl control-plane HTTP API server: its
// lifecycle, middleware chain (request-id + request-scoped logging, security
// headers, access logging, panic recovery), the health/readiness/version/OpenAPI
// endpoints, the domain-error→HTTP mapping, and graceful shutdown (S1).
//
// Handlers are thin: they return domain errors (internal/apierror) and the
// adapter maps them to status codes. Every request carries a context capable of
// holding tenant identity, which S2 resolves (internal/tenancy). Versioned
// resource endpoints under /v1 are added by later sprints (S9+).
package control
