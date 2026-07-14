// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
